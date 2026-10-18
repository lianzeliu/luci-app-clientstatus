/*
 * traffic.c — MTK 硬件加速感知的流量统计引擎
 *
 * 数据源:
 *   有线 / 回退 : /proc/net/nf_conntrack 的 bytes= 累计值
 *   WiFi 优先   : ubus iwinfo assoclist 的 per-station tx/rx.bytes (mt76 驱动)
 *
 * 关键正确性保证:
 *  - 逐流 (五元组) 维护基线, 只累计增量; 流老化/重建不污染累计值。
 *  - 实时速率 = 30 秒滑动窗口内的 (累计差 / 时间差), 不把内核 GC
 *    批量同步的字节算到 1 秒里 (之前"实时偏高 2-3 倍"的根因)。
 *  - 区分 [HW_OFFLOAD] 流, 单独累计硬件加速字节。
 *  - 内网 IP 做目的端的流 (外部主动连入) 也归属, 不止看 src=。
 *  - IPv4 + IPv6。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include "traffic.h"

#define ML 18
#define TRAF_FILE   "/tmp/clientstatus.traffic"
#define CT_PATH     "/proc/net/nf_conntrack"
#define ACCT_PATH   "/proc/sys/net/netfilter/nf_conntrack_acct"
#define ARP_PATH    "/proc/net/arp"
#define LEASES_PATH "/tmp/dhcp.leases"

#define TRAF_TICK     2    /* 采样间隔(秒) */
#define TRAF_WIN      30   /* 速率滑动窗口(秒) */
#define TRAF_SLOTS    18   /* 环形槽位数 >= WIN/TICK + 3 */
#define WIFI_EVERY    5    /* 每 N 个 tick 采样一次 iwinfo */
#define DRV_STALE_MAX 3    /* 驱动计数连续冻结 N 次且 conntrack 有流量 -> 回退 */
#define MAX_CLI       512
#define FLOW_BUCKETS  4096
#define MAX_LINE      4096

/* ─── IP -> MAC 映射 ─────────────────────────────── */

typedef struct {
    int v6;
    uint32_t v4;            /* network byte order */
    struct in6_addr a6;
    char mac[ML];
} IpMac;

static IpMac g_map[1024];
static int g_map_n;
static char g_lan[32] = "br-lan";

static int valid_mac(const char *m) {
    if (!m || strlen(m) != 17) return 0;
    for (int i = 0; i < 17; i++) {
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if (m[i] != ':') return 0;
        } else if (!isxdigit((unsigned char)m[i])) return 0;
    }
    return 1;
}

static void upper(char *s)
    { for (; *s; s++) *s = toupper((unsigned char)*s); }

static void map_add_v4(uint32_t v4, const char *mac) {
    if (g_map_n >= 1024 || !valid_mac(mac)) return;
    for (int i = 0; i < g_map_n; i++)
        if (!g_map[i].v6 && g_map[i].v4 == v4) return;
    g_map[g_map_n].v6 = 0;
    g_map[g_map_n].v4 = v4;
    strncpy(g_map[g_map_n].mac, mac, ML - 1);
    g_map[g_map_n].mac[ML - 1] = '\0';
    upper(g_map[g_map_n].mac);
    g_map_n++;
}

static void map_add_v6(const struct in6_addr *a6, const char *mac) {
    if (g_map_n >= 1024 || !valid_mac(mac)) return;
    for (int i = 0; i < g_map_n; i++)
        if (g_map[i].v6 && memcmp(&g_map[i].a6, a6, 16) == 0) return;
    g_map[g_map_n].v6 = 1;
    g_map[g_map_n].a6 = *a6;
    strncpy(g_map[g_map_n].mac, mac, ML - 1);
    g_map[g_map_n].mac[ML - 1] = '\0';
    upper(g_map[g_map_n].mac);
    g_map_n++;
}

/* 从 dhcp.leases / arp / v6 neigh 重建映射 */
void traf_rebuild_map(void) {
    g_map_n = 0;
    FILE *f;
    char line[512];

    f = fopen(LEASES_PATH, "r");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            long ts; char mac[ML], ip[16], host[128], cid[128];
            if (sscanf(line, "%ld %17s %15s %127s %127s",
                       &ts, mac, ip, host, cid) < 4) continue;
            struct in_addr a;
            if (inet_aton(ip, &a))
                map_add_v4(a.s_addr, mac);
        }
        fclose(f);
    }

    f = fopen(ARP_PATH, "r");
    if (f) {
        if (fgets(line, sizeof line, f)) { /* header */
            while (fgets(line, sizeof line, f)) {
                char ip[16], hw[16], fl[16], mac[ML], mk[16], dv[32];
                if (sscanf(line, "%15s %15s %15s %17s %15s %31s",
                           ip, hw, fl, mac, mk, dv) < 6) continue;
                if (strcmp(dv, g_lan) != 0) continue;
                if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
                struct in_addr a;
                if (inet_aton(ip, &a))
                    map_add_v4(a.s_addr, mac);
            }
        }
        fclose(f);
    }

    /* IPv6 neighbor 表 */
    {
        char cmd[96];
        snprintf(cmd, sizeof cmd, "ip -6 neigh show dev %s 2>/dev/null", g_lan);
        f = popen(cmd, "r");
        if (f) {
            while (fgets(line, sizeof line, f)) {
                /* fd00::5 dev br-lan lladdr AA:BB:..:FF REACHABLE */
                char ip[64], dev[32], ll[8], mac[ML], st[16];
                if (sscanf(line, "%63s %31s %7s %17s %15s",
                           ip, dev, ll, mac, st) < 5) continue;
                if (strcmp(ll, "lladdr") != 0) continue;
                if (strcmp(st, "FAILED") == 0 || strcmp(st, "INCOMPLETE") == 0)
                    continue;
                struct in6_addr a6;
                if (inet_pton(AF_INET6, ip, &a6) == 1)
                    map_add_v6(&a6, mac);
            }
            pclose(f);
        }
    }
}

/* ─── conntrack 行解析 ───────────────────────────── */

typedef struct {
    uint8_t l3;             /* 4 / 6 */
    uint8_t proto;
    uint8_t saddr[16], daddr[16];  /* v4 用前 4 字节 */
    uint16_t sport, dport;
    uint64_t up, down;      /* 原方向 / 回包方向 bytes */
    int hw;                 /* [HW_OFFLOAD] */
} CtFlow;

/* 解析一行, 成功返回 1 */
static int parse_ct_line(const char *line, CtFlow *cf) {
    memset(cf, 0, sizeof *cf);
    if (strncmp(line, "ipv4", 4) == 0) cf->l3 = 4;
    else if (strncmp(line, "ipv6", 4) == 0) cf->l3 = 6;
    else return 0;
    cf->hw = (strstr(line, "[HW_OFFLOAD]") != NULL);

    char saddr_s[64] = "", daddr_s[64] = "";
    int nsrc = 0, ndst = 0, nsp = 0, ndp = 0, nbytes = 0, tok = 0;
    const char *p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        const char *t = p;
        while (*p && !isspace((unsigned char)*p)) p++;

        if (tok == 3) {
            char tmp[16]; int l = p - t;
            if (l > 0 && l < 16) {
                memcpy(tmp, t, l); tmp[l] = '\0';
                cf->proto = (uint8_t)atoi(tmp);
            }
        } else if (strncmp(t, "src=", 4) == 0) {
            if (nsrc == 0) {
                int l = p - (t + 4);
                if (l > 0 && l < 64) { memcpy(saddr_s, t + 4, l); saddr_s[l] = '\0'; }
            }
            nsrc++;
        } else if (strncmp(t, "dst=", 4) == 0) {
            if (ndst == 0) {
                int l = p - (t + 4);
                if (l > 0 && l < 64) { memcpy(daddr_s, t + 4, l); daddr_s[l] = '\0'; }
            }
            ndst++;
        } else if (strncmp(t, "sport=", 6) == 0) {
            if (nsp == 0) cf->sport = (uint16_t)atoi(t + 6);
            nsp++;
        } else if (strncmp(t, "dport=", 6) == 0) {
            if (ndp == 0) cf->dport = (uint16_t)atoi(t + 6);
            ndp++;
        } else if (strncmp(t, "bytes=", 6) == 0) {
            uint64_t v = strtoull(t + 6, NULL, 10);
            if (nbytes == 0) cf->up = v;
            else if (nbytes == 1) cf->down = v;
            nbytes++;
        }
        tok++;
    }
    if (!saddr_s[0] || !daddr_s[0] || nbytes == 0) return 0;

    if (cf->l3 == 4) {
        struct in_addr a, b;
        if (!inet_aton(saddr_s, &a) || !inet_aton(daddr_s, &b)) return 0;
        memcpy(cf->saddr, &a.s_addr, 4);
        memcpy(cf->daddr, &b.s_addr, 4);
    } else {
        struct in6_addr a, b;
        if (inet_pton(AF_INET6, saddr_s, &a) != 1 ||
            inet_pton(AF_INET6, daddr_s, &b) != 1) return 0;
        memcpy(cf->saddr, &a, 16);
        memcpy(cf->daddr, &b, 16);
    }
    return 1;
}

/* ─── 逐流基线表 (增量核心) ───────────────────────── */

typedef struct FlowE {
    uint8_t l3, proto;
    uint8_t saddr[16], daddr[16];
    uint16_t sport, dport;
    uint64_t up, down;
    int seen;
    struct FlowE *next;
} FlowE;

static FlowE *g_flows[FLOW_BUCKETS];

static unsigned flow_hash(const CtFlow *cf) {
    /* djb2 over 五元组 */
    unsigned h = 5381;
    h = h * 33 + cf->l3;
    h = h * 33 + cf->proto;
    int alen = (cf->l3 == 4) ? 4 : 16;
    for (int i = 0; i < alen; i++) h = h * 33 + cf->saddr[i];
    for (int i = 0; i < alen; i++) h = h * 33 + cf->daddr[i];
    h = h * 33 + (cf->sport >> 8); h = h * 33 + (cf->sport & 0xff);
    h = h * 33 + (cf->dport >> 8); h = h * 33 + (cf->dport & 0xff);
    return h % FLOW_BUCKETS;
}

static int flow_eq(const FlowE *e, const CtFlow *cf) {
    int alen = (cf->l3 == 4) ? 4 : 16;
    return e->l3 == cf->l3 && e->proto == cf->proto &&
           e->sport == cf->sport && e->dport == cf->dport &&
           memcmp(e->saddr, cf->saddr, alen) == 0 &&
           memcmp(e->daddr, cf->daddr, alen) == 0;
}

/* 查找; create=1 时不存在则新建(基线=当前值, 增量 0) */
static FlowE *flow_lookup(const CtFlow *cf, int create) {
    unsigned h = flow_hash(cf);
    for (FlowE *e = g_flows[h]; e; e = e->next)
        if (flow_eq(e, cf)) return e;
    if (!create) return NULL;
    FlowE *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->l3 = cf->l3; e->proto = cf->proto;
    int alen = (cf->l3 == 4) ? 4 : 16;
    memcpy(e->saddr, cf->saddr, alen);
    memcpy(e->daddr, cf->daddr, alen);
    e->sport = cf->sport; e->dport = cf->dport;
    e->up = cf->up; e->down = cf->down;
    e->next = g_flows[h];
    g_flows[h] = e;
    return e;
}

/* 回收本轮没出现的流 (老化) */
static void flow_gc(void) {
    for (int i = 0; i < FLOW_BUCKETS; i++) {
        FlowE **pp = &g_flows[i];
        while (*pp) {
            if (!(*pp)->seen) {
                FlowE *dead = *pp;
                *pp = dead->next;
                free(dead);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

/* ─── 每客户端状态 ─────────────────────────────────── */

typedef struct {
    char mac[ML];
    char ip[48];
    uint64_t rx_hist[TRAF_SLOTS], tx_hist[TRAF_SLOTS];
    uint64_t hwr_hist[TRAF_SLOTS], hwt_hist[TRAF_SLOTS];
    time_t ts_hist[TRAF_SLOTS];
    int head, n;
    double rx_spd, tx_spd;                 /* 字节/秒, 30s 窗口 */
    uint64_t rx_tot, tx_tot;              /* 累计 (单调) */
    uint64_t hwr_tot, hwt_tot;            /* 累计硬件加速字节 */
    /* WiFi 驱动计数 */
    uint64_t drv_rx, drv_tx;
    int drv_frozen, drv_changing, use_drv;
    /* conntrack 影子计数 (use_drv=1 时用于检测驱动冻结) */
    uint64_t ct_up_win, ct_down_win, ct_hwu_win, ct_hwd_win;
} TrafCli;

static TrafCli g_cli[MAX_CLI];
static int g_cli_n;

static TrafCli *traf_find(const char *mac, int create) {
    for (int i = 0; i < g_cli_n; i++)
        if (strcasecmp(g_cli[i].mac, mac) == 0) return &g_cli[i];
    if (!create || g_cli_n >= MAX_CLI) return NULL;
    TrafCli *tc = &g_cli[g_cli_n++];
    memset(tc, 0, sizeof *tc);
    strncpy(tc->mac, mac, ML - 1);
    tc->mac[ML - 1] = '\0';
    upper(tc->mac);
    /* 回填 IP (map 里第一个命中的) */
    for (int i = 0; i < g_map_n; i++) {
        if (strcasecmp(g_map[i].mac, tc->mac) == 0) {
            if (g_map[i].v6)
                inet_ntop(AF_INET6, &g_map[i].a6, tc->ip, sizeof tc->ip);
            else {
                struct in_addr a; a.s_addr = g_map[i].v4;
                inet_ntop(AF_INET, &a, tc->ip, sizeof tc->ip);
            }
            break;
        }
    }
    return tc;
}

static void traf_reset_ring(TrafCli *tc) {
    tc->head = 0; tc->n = 0;
    tc->rx_spd = tc->tx_spd = 0;
}

/* ─── IP 归属 ──────────────────────────────────────── */

static const char *ipmac_lookup(const CtFlow *cf, int use_src) {
    const uint8_t *a = use_src ? cf->saddr : cf->daddr;
    int alen = (cf->l3 == 4) ? 4 : 16;
    for (int i = 0; i < g_map_n; i++) {
        if (g_map[i].v6 != (cf->l3 == 6)) continue;
        const uint8_t *b = g_map[i].v6 ? (const uint8_t *)&g_map[i].a6
                                       : (const uint8_t *)&g_map[i].v4;
        if (memcmp(a, b, alen) == 0) return g_map[i].mac;
    }
    return NULL;
}

/* ─── conntrack 采样 ───────────────────────────────── */

typedef struct {
    char mac[ML];
    uint64_t up, down, hwu, hwd;
} MacSum;

static int sum_find(MacSum *sums, int *n, const char *mac) {
    for (int i = 0; i < *n; i++)
        if (strcasecmp(sums[i].mac, mac) == 0) return i;
    if (*n >= MAX_CLI) return -1;
    strncpy(sums[*n].mac, mac, ML - 1);
    sums[*n].mac[ML - 1] = '\0';
    upper(sums[*n].mac);
    return (*n)++;
}

static void sample_conntrack_file(FILE *f) {
    char line[MAX_LINE];
    MacSum sums[MAX_CLI];
    int sums_n = 0;
    memset(sums, 0, sizeof sums);

    for (int i = 0; i < FLOW_BUCKETS; i++)
        for (FlowE *e = g_flows[i]; e; e = e->next) e->seen = 0;

    while (fgets(line, sizeof line, f)) {
        CtFlow cf;
        if (!parse_ct_line(line, &cf)) continue;
        FlowE *e = flow_lookup(&cf, 1);
        if (!e) continue;
        uint64_t du = (cf.up > e->up) ? cf.up - e->up : 0;
        uint64_t dd = (cf.down > e->down) ? cf.down - e->down : 0;
        e->up = cf.up; e->down = cf.down; e->seen = 1;
        if (du == 0 && dd == 0) continue;

        /* 归属: 先看原方向 src, 再看 dst (外部主动连入的场景) */
        const char *mac = ipmac_lookup(&cf, 1);
        int lan_is_src = 1;
        if (!mac) { mac = ipmac_lookup(&cf, 0); lan_is_src = 0; }
        if (!mac) continue;

        uint64_t up = lan_is_src ? du : dd;    /* 客户端上传 */
        uint64_t down = lan_is_src ? dd : du;  /* 客户端下载 */

        TrafCli *tc = traf_find(mac, 1);
        if (tc && tc->use_drv) {
            /* 驱动模式: 只记影子计数用于冻结检测, 不进累计 */
            tc->ct_up_win += up; tc->ct_down_win += down;
            if (cf.hw) { tc->ct_hwu_win += up; tc->ct_hwd_win += down; }
            continue;
        }
        int si = sum_find(sums, &sums_n, mac);
        if (si < 0) continue;
        sums[si].up += up; sums[si].down += down;
        if (cf.hw) { sums[si].hwu += up; sums[si].hwd += down; }
    }
    flow_gc();

    for (int i = 0; i < sums_n; i++) {
        TrafCli *tc = traf_find(sums[i].mac, 1);
        if (!tc) continue;
        tc->rx_tot += sums[i].down;
        tc->tx_tot += sums[i].up;
        tc->hwr_tot += sums[i].hwd;
        tc->hwt_tot += sums[i].hwu;
    }
}

/* ─── WiFi 驱动采样 (iwinfo per-station) ────────────── */

static char g_aps[32][32];
static int g_aps_n;
static int g_drv_ok;   /* 驱动是否上报 per-station 字节 (初始探测结果) */

void traf_set_wifi(const char (*ifnames)[32], int n, int drv_ok) {
    g_aps_n = 0;
    if (ifnames) {
        for (int i = 0; i < n && g_aps_n < 32; i++) {
            strncpy(g_aps[g_aps_n], ifnames[i], 31);
            g_aps[g_aps_n][31] = '\0';
            g_aps_n++;
        }
    }
    g_drv_ok = drv_ok;
}

/* 在 station 对象范围内找 "tx" -> "bytes": 数字 */
static uint64_t station_bytes(const char *base, const char *end, const char *dir) {
    const char *p = strstr(base, dir);
    if (!p || (end && p >= end)) return 0;
    p = strstr(p, "\"bytes\"");
    if (!p || (end && p >= end)) return 0;
    p = strchr(p, ':');
    if (!p || (end && p >= end)) return 0;
    return strtoull(p + 1, NULL, 10);
}

static void sample_wifi(void) {
    if (g_aps_n == 0) return;
    for (int a = 0; a < g_aps_n; a++) {
        char cmd[160];
        snprintf(cmd, sizeof cmd,
                 "ubus call iwinfo assoclist '{\"device\":\"%.31s\"}' 2>/dev/null",
                 g_aps[a]);
        FILE *f = popen(cmd, "r");
        if (!f) continue;

        /* 读全输出 (动态缓冲) */
        size_t cap = 65536, len = 0;
        char *buf = malloc(cap);
        if (!buf) { pclose(f); continue; }
        size_t r;
        while ((r = fread(buf + len, 1, cap - len - 1, f)) > 0) {
            len += r;
            if (len + 1 >= cap) {
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) break;
                buf = nb;
            }
        }
        pclose(f);
        buf[len] = '\0';

        const char *p = buf;
        while ((p = strstr(p, "\"mac\"")) != NULL) {
            const char *vend = strstr(p + 5, "\"mac\""); /* 下一个 station 的边界 */
            char mac[ML] = "";
            const char *q = strchr(p, ':');
            if (q) {
                q++;
                while (*q && isspace((unsigned char)*q)) q++;
                if (*q == '"' && strlen(q + 1) >= 17) {
                    memcpy(mac, q + 1, 17); mac[17] = '\0';
                }
            }
            if (valid_mac(mac)) {
                /* iwinfo: tx = AP 发出 = 客户端下行(rx); rx = AP 收到 = 客户端上行(tx) */
                uint64_t ap_tx = station_bytes(p, vend, "\"tx\"");
                uint64_t ap_rx = station_bytes(p, vend, "\"rx\"");
                uint64_t c_rx = ap_tx, c_tx = ap_rx;

                TrafCli *tc = traf_find(mac, 1);
                if (tc) {
                    if (!tc->use_drv) {
                        /* 驱动模式未启用: 观察计数器是否在走, 连续 2 次变化则切入 */
                        if (c_rx != tc->drv_rx || c_tx != tc->drv_tx)
                            tc->drv_changing++;
                        else
                            tc->drv_changing = 0;
                        tc->drv_rx = c_rx; tc->drv_tx = c_tx;
                        if (g_drv_ok && tc->drv_changing >= 2) {
                            tc->use_drv = 1;
                            tc->drv_frozen = 0;
                            traf_reset_ring(tc);
                        }
                    } else {
                        if (c_rx < tc->drv_rx || c_tx < tc->drv_tx) {
                            /* 重关联: 驱动计数器重置 */
                            traf_reset_ring(tc);
                            tc->drv_rx = c_rx; tc->drv_tx = c_tx;
                            tc->drv_frozen = 0;
                        } else if (c_rx == tc->drv_rx && c_tx == tc->drv_tx) {
                            tc->drv_frozen++;
                            if (tc->drv_frozen >= DRV_STALE_MAX &&
                                (tc->ct_up_win + tc->ct_down_win) > 0) {
                                /* 驱动冻结 (WED 等) 但 conntrack 有流量 -> 回退 */
                                tc->rx_tot += tc->ct_down_win;
                                tc->tx_tot += tc->ct_up_win;
                                tc->hwr_tot += tc->ct_hwd_win;
                                tc->hwt_tot += tc->ct_hwu_win;
                                tc->use_drv = 0;
                                tc->drv_changing = 0;
                                traf_reset_ring(tc);
                            }
                        } else {
                            tc->rx_tot += c_rx - tc->drv_rx;
                            tc->tx_tot += c_tx - tc->drv_tx;
                            tc->drv_rx = c_rx; tc->drv_tx = c_tx;
                            tc->drv_frozen = 0;
                        }
                    }
                    tc->ct_up_win = tc->ct_down_win = 0;
                    tc->ct_hwu_win = tc->ct_hwd_win = 0;
                }
            }
            p = vend ? vend : p + 5;
            if (!vend) break;
        }
        free(buf);
    }
}

/* ─── 滑动窗口速率 + 落盘 ───────────────────────────── */

static void push_sample(TrafCli *tc, time_t now) {
    tc->head = (tc->head + 1) % TRAF_SLOTS;
    tc->rx_hist[tc->head] = tc->rx_tot;
    tc->tx_hist[tc->head] = tc->tx_tot;
    tc->hwr_hist[tc->head] = tc->hwr_tot;
    tc->hwt_hist[tc->head] = tc->hwt_tot;
    tc->ts_hist[tc->head] = now;
    if (tc->n < TRAF_SLOTS) tc->n++;

    int oldest = tc->head;
    int idx = tc->head;
    for (int k = 1; k < tc->n; k++) {
        idx = (idx - 1 + TRAF_SLOTS) % TRAF_SLOTS;
        if (now - tc->ts_hist[idx] > TRAF_WIN) break;
        oldest = idx;
    }
    double dt = (double)(tc->ts_hist[tc->head] - tc->ts_hist[oldest]);
    if (dt >= 2 * TRAF_TICK && tc->rx_hist[tc->head] >= tc->rx_hist[oldest]) {
        tc->rx_spd = (double)(tc->rx_hist[tc->head] - tc->rx_hist[oldest]) / dt;
        tc->tx_spd = (double)(tc->tx_hist[tc->head] - tc->tx_hist[oldest]) / dt;
    } else {
        tc->rx_spd = tc->tx_spd = 0;
    }
}

static void traf_write_file(time_t now) {
    char tmp[64];
    snprintf(tmp, sizeof tmp, "%s.tmp", TRAF_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "# clientstatus traffic | ts=%ld win=%d\n", (long)now, TRAF_WIN);
    fprintf(f, "# MAC|IP|RX_SPD|TX_SPD|RX_TOT|TX_TOT|HW_RX|HW_TX\n");
    for (int i = 0; i < g_cli_n; i++) {
        TrafCli *tc = &g_cli[i];
        fprintf(f, "%s|%s|%llu|%llu|%llu|%llu|%llu|%llu\n",
                tc->mac, tc->ip[0] ? tc->ip : "-",
                (unsigned long long)(tc->rx_spd + 0.5),
                (unsigned long long)(tc->tx_spd + 0.5),
                (unsigned long long)tc->rx_tot,
                (unsigned long long)tc->tx_tot,
                (unsigned long long)tc->hwr_tot,
                (unsigned long long)tc->hwt_tot);
    }
    fclose(f);
    rename(tmp, TRAF_FILE);
}

/* ─── 对外接口 ─────────────────────────────────────── */

static void ensure_acct(void) {
    FILE *f = fopen(ACCT_PATH, "r");
    if (f) {
        char b[16] = "";
        if (!fgets(b, sizeof b, f)) b[0] = '\0';
        fclose(f);
        if (atoi(b) == 1) return;
    }
    f = fopen(ACCT_PATH, "w");
    if (f) {
        fputs("1\n", f);
        fclose(f);
        fprintf(stderr, "traffic: enabled net.netfilter.nf_conntrack_acct\n");
    } else {
        fprintf(stderr, "traffic: WARNING cannot enable nf_conntrack_acct; "
                        "traffic stats will be empty\n");
    }
}

void traf_init(const char *lan_iface) {
    if (lan_iface && lan_iface[0]) {
        strncpy(g_lan, lan_iface, sizeof g_lan - 1);
        g_lan[sizeof g_lan - 1] = '\0';
    }
    ensure_acct();
    traf_rebuild_map();
}

void traf_tick(void) {
    static int tick = 0;
    time_t now = time(NULL);
    tick++;

    FILE *f = fopen(CT_PATH, "r");
    if (f) {
        sample_conntrack_file(f);
        fclose(f);
    }

    if (g_aps_n > 0 && tick % WIFI_EVERY == 0)
        sample_wifi();

    for (int i = 0; i < g_cli_n; i++)
        push_sample(&g_cli[i], now);

    traf_write_file(now);
}
