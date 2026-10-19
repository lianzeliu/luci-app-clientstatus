/*
 * traffic.c — 流量统计引擎 (conntrack 单数据源重写版)
 *
 * 设计:
 *  - 单数据源: /proc/net/nf_conntrack, 解析 ALL 流 (不再只限 [HW_OFFLOAD])。
 *    前提: net.netfilter.nf_conntrack_acct=1 (daemon 启动时自动开启),
 *    此时软件转发和硬件加速流都有 packets=/bytes= 计数。
 *  - per-flow (5 元组) 基线: 只计增量, 免疫计数器回绕/重建;
 *    新流首见永远先建基线 (init 标记), 不把累计值当增量。
 *  - IP->MAC 经 ARP/neighbor 表归属; 两端都是 LAN 的流跳过 (只计 WAN)。
 *  - 速率: 1s 采样, 3s 滑动窗口; 连续 2 tick 累计不变直接判停为 0。
 *    窗口短 + 判停快, 空闲时不拖尾、不虚高。
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

#define TRAF_WIN      3    /* 速率滑动窗口(秒): 短窗口, 停得快 */
#define TRAF_SLOTS    5    /* 环形槽位数 >= WIN/TICK + 2 */
#define FLAT_SNAP     2    /* 连续 N 个 tick 累计不变 -> 直接判停, 速率置 0 */
#define MAX_CLI       512
#define FLOW_BUCKETS  4096
#define MAX_LINE      4096

/* ─── IP->MAC 映射 ─────────────────────────────────── */

typedef struct {
    uint32_t v4;
    struct in6_addr a6;
    int v6;
    char mac[ML];
} IpMac;

static IpMac g_map[1024];
static int g_map_n;

static int valid_mac(const char *m) {
    if (!m) return 0;
    int n = 0;
    for (const char *p = m; *p; p++) {
        if (*p == ':') n++;
        else if (!isxdigit((unsigned char)*p)) return 0;
    }
    return n == 5 && strlen(m) == 17;
}

static void upper(char *s) {
    for (; *s; s++) *s = toupper((unsigned char)*s);
}

static void mac_copy(char *dst, const char *src) {
    size_t n = strlen(src);
    if (n >= ML) n = ML - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void map_add_v4(uint32_t v4, const char *mac) {
    if (!valid_mac(mac) || g_map_n >= 1024) return;
    for (int i = 0; i < g_map_n; i++)
        if (!g_map[i].v6 && g_map[i].v4 == v4) {
            mac_copy(g_map[i].mac, mac); upper(g_map[i].mac);
            return;
        }
    g_map[g_map_n].v4 = v4;
    g_map[g_map_n].v6 = 0;
    mac_copy(g_map[g_map_n].mac, mac); upper(g_map[g_map_n].mac);
    g_map_n++;
}

static void map_add_v6(const struct in6_addr *a6, const char *mac) {
    if (!valid_mac(mac) || g_map_n >= 1024) return;
    for (int i = 0; i < g_map_n; i++)
        if (g_map[i].v6 && memcmp(&g_map[i].a6, a6, 16) == 0) {
            mac_copy(g_map[i].mac, mac); upper(g_map[i].mac);
            return;
        }
    g_map[g_map_n].a6 = *a6;
    g_map[g_map_n].v6 = 1;
    mac_copy(g_map[g_map_n].mac, mac); upper(g_map[g_map_n].mac);
    g_map_n++;
}

static const char *map_lookup_v4(uint32_t v4) {
    for (int i = 0; i < g_map_n; i++)
        if (!g_map[i].v6 && g_map[i].v4 == v4) return g_map[i].mac;
    return NULL;
}

static const char *map_lookup_v6(const struct in6_addr *a6) {
    for (int i = 0; i < g_map_n; i++)
        if (g_map[i].v6 && memcmp(&g_map[i].a6, a6, 16) == 0) return g_map[i].mac;
    return NULL;
}

/* 从 ARP 表 + DHCP leases 重建 IP->MAC 映射 */
void traf_rebuild_map(void) {
    g_map_n = 0;
    FILE *f = fopen(ARP_PATH, "r");
    if (f) {
        char line[MAX_LINE];
        fgets(line, sizeof line, f); /* 跳过表头 */
        while (fgets(line, sizeof line, f)) {
            char ip[64], hw[16], fl[16], mac[ML], mk[16], dv[32];
            if (sscanf(line, "%63s %15s %15s %17s %15s %31s",
                       ip, hw, fl, mac, mk, dv) == 6) {
                if (!valid_mac(mac)) continue;
                struct in_addr a;
                if (inet_pton(AF_INET, ip, &a) == 1)
                    map_add_v4(a.s_addr, mac);
            }
        }
        fclose(f);
    }
    /* neighbor 表 (IPv6) */
    f = popen("ip -6 neigh show 2>/dev/null", "r");
    if (f) {
        char line[MAX_LINE];
        while (fgets(line, sizeof line, f)) {
            char ip[64], dev[32], ll[8], mac[ML], st[16];
            if (sscanf(line, "%63s dev %31s lladdr %17s %15s",
                       ip, dev, mac, st) >= 3) {
                if (!valid_mac(mac)) continue;
                struct in6_addr a6;
                if (inet_pton(AF_INET6, ip, &a6) == 1) {
                    if (IN6_IS_ADDR_LOOPBACK(&a6) ||
                        IN6_IS_ADDR_MULTICAST(&a6)) continue;
                    map_add_v6(&a6, mac);
                }
            }
        }
        pclose(f);
    }
}

/* ─── 客户端累计 ─────────────────────────────────── */

typedef struct {
    char mac[ML];
    char ip[64];
    uint64_t rx_hist[TRAF_SLOTS], tx_hist[TRAF_SLOTS];
    time_t ts_hist[TRAF_SLOTS];
    int head, n;
    double rx_spd, tx_spd;                 /* 字节/秒, 滑动窗口 */
    uint64_t rx_tot, tx_tot;              /* 累计 (单调) */
    uint64_t prev_tot;                    /* 上 tick 的 rx+tx, 用于判停 */
    int flat_ticks;                       /* 连续累计不变的 tick 数 */
} TrafCli;

static TrafCli g_cli[MAX_CLI];
static int g_cli_n;

static TrafCli *traf_find(const char *mac, int create) {
    for (int i = 0; i < g_cli_n; i++)
        if (strcasecmp(g_cli[i].mac, mac) == 0) return &g_cli[i];
    if (!create || g_cli_n >= MAX_CLI) return NULL;
    TrafCli *tc = &g_cli[g_cli_n++];
    memset(tc, 0, sizeof *tc);
    mac_copy(tc->mac, mac);
    upper(tc->mac);
    /* 回填 IP (map 里第一个命中的) */
    for (int i = 0; i < g_map_n; i++) {
        if (strcasecmp(g_map[i].mac, tc->mac) == 0) {
            if (g_map[i].v6)
                inet_ntop(AF_INET6, &g_map[i].a6, tc->ip, sizeof tc->ip);
            else {
                struct in_addr a = { .s_addr = g_map[i].v4 };
                inet_ntop(AF_INET, &a, tc->ip, sizeof tc->ip);
            }
            break;
        }
    }
    return tc;
}

/* ─── per-flow 基线 ───────────────────────────────── */

typedef struct {
    uint8_t l3;      /* 4 或 6 */
    uint8_t proto;
    uint8_t saddr[16], daddr[16];
    uint16_t sport, dport;
    uint64_t up, down;   /* 两个方向的累计 bytes */
} CtFlow;

typedef struct {
    char key[128];
    uint64_t up, down;
    int seen;
    int init;  /* 基线是否已初始化 */
} HwFlow;

static HwFlow g_flows[FLOW_BUCKETS];
static int g_flow_n;

static unsigned flow_hash(const char *k) {
    unsigned h = 5381;
    while (*k) h = h * 33 + (unsigned char)*k++;
    return h % FLOW_BUCKETS;
}

static HwFlow *flow_find(const char *key, int create) {
    unsigned h = flow_hash(key);
    for (int i = 0; i < FLOW_BUCKETS; i++) {
        unsigned idx = (h + i) % FLOW_BUCKETS;
        if (g_flows[idx].key[0] == '\0') {
            if (!create) return NULL;
            size_t kl = strlen(key);
            if (kl >= sizeof g_flows[idx].key) kl = sizeof g_flows[idx].key - 1;
            memcpy(g_flows[idx].key, key, kl);
            g_flows[idx].key[kl] = '\0';
            g_flow_n++;
            return &g_flows[idx];
        }
        if (strcmp(g_flows[idx].key, key) == 0) return &g_flows[idx];
    }
    return NULL;
}

static void flow_gc(void) {
    for (int i = 0; i < FLOW_BUCKETS; i++) {
        if (g_flows[i].key[0] && !g_flows[i].seen) {
            g_flows[i].key[0] = '\0';
            g_flows[i].up = g_flows[i].down = 0;
            g_flows[i].init = 0;
            g_flow_n--;
        } else g_flows[i].seen = 0;
    }
}

/* 解析一行 conntrack, 提取 5 元组 + 双向 bytes.
 * 接受所有流 (不再只限 [HW_OFFLOAD]), 只要有 bytes= 就计入。
 * 返回 1 成功, 0 跳过。 */
static int parse_ct_line(const char *line, CtFlow *cf) {
    memset(cf, 0, sizeof *cf);
    if (strncmp(line, "ipv4", 4) == 0) cf->l3 = 4;
    else if (strncmp(line, "ipv6", 4) == 0) cf->l3 = 6;
    else return 0;

    char saddr_s[64] = "", daddr_s[64] = "";
    int nsrc = 0, ndst = 0, nbytes = 0, tok = 0;
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
            if (nsrc == 1) cf->sport = (uint16_t)atoi(t + 6);
            else cf->dport = (uint16_t)atoi(t + 6);
        } else if (strncmp(t, "dport=", 6) == 0) {
            if (nsrc == 1) cf->dport = (uint16_t)atoi(t + 6);
            else cf->sport = (uint16_t)atoi(t + 6);
        } else if (strncmp(t, "bytes=", 6) == 0) {
            uint64_t b = strtoull(t + 6, NULL, 10);
            if (nbytes == 0) cf->up = b; else cf->down = b;
            nbytes++;
        }
        tok++;
    }
    if (nbytes < 2) return 0;  /* 需要双向 bytes */

    /* 解析 IP */
    if (cf->l3 == 4) {
        struct in_addr a;
        if (inet_pton(AF_INET, saddr_s, &a) != 1) return 0;
        memcpy(cf->saddr, &a.s_addr, 4);
        if (inet_pton(AF_INET, daddr_s, &a) != 1) return 0;
        memcpy(cf->daddr, &a.s_addr, 4);
    } else {
        struct in6_addr a6;
        if (inet_pton(AF_INET6, saddr_s, &a6) != 1) return 0;
        memcpy(cf->saddr, &a6, 16);
        if (inet_pton(AF_INET6, daddr_s, &a6) != 1) return 0;
        memcpy(cf->daddr, &a6, 16);
    }
    return 1;
}

/* 内网 IP 归属: 返回 MAC, 或 NULL (非内网/未知) */
static const char *ct_ipmac(const CtFlow *cf, int use_src) {
    const uint8_t *ip = use_src ? cf->saddr : cf->daddr;
    if (cf->l3 == 4) {
        uint32_t v4;
        memcpy(&v4, ip, 4);
        /* 跳过回环/组播 */
        uint32_t h = ntohl(v4);
        if ((h >> 24) == 127 || (h >> 28) == 0xE) return NULL;
        return map_lookup_v4(v4);
    } else {
        struct in6_addr a6;
        memcpy(&a6, ip, 16);
        if (IN6_IS_ADDR_LOOPBACK(&a6) || IN6_IS_ADDR_MULTICAST(&a6)) return NULL;
        return map_lookup_v6(&a6);
    }
}

/* 采样 conntrack: per-flow 基线计增量, 归属到客户端 */
static void ct_sample(void) {
    FILE *f = fopen(CT_PATH, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof line, f)) {
        CtFlow cf;
        if (!parse_ct_line(line, &cf)) continue;

        char key[128];
        if (cf.l3 == 4)
            snprintf(key, sizeof key, "4/%u/%08x/%08x/%u/%u", cf.proto,
                     *(uint32_t *)cf.saddr, *(uint32_t *)cf.daddr,
                     cf.sport, cf.dport);
        else
            snprintf(key, sizeof key, "6/%u/%02x%02x/%02x%02x/%u/%u", cf.proto,
                     cf.saddr[14], cf.saddr[15], cf.daddr[14], cf.daddr[15],
                     cf.sport, cf.dport);

        HwFlow *e = flow_find(key, 1);
        if (!e) continue;
        e->seen = 1;
        if (!e->init) {
            e->up = cf.up; e->down = cf.down;
            e->init = 1;
            continue;  /* 首见建基线, 不计增量 */
        }
        uint64_t du = (cf.up > e->up) ? cf.up - e->up : 0;
        uint64_t dd = (cf.down > e->down) ? cf.down - e->down : 0;
        e->up = cf.up; e->down = cf.down;
        if (du == 0 && dd == 0) continue;

        /* 归属: src/dst 谁是内网客户端 */
        const char *mac_s = ct_ipmac(&cf, 1);
        const char *mac_d = ct_ipmac(&cf, 0);
        if (mac_s && mac_d) continue;  /* LAN 互访, 只计 WAN */
        const char *mac = mac_s ? mac_s : mac_d;
        if (!mac) continue;
        int lan_is_src = (mac_s != NULL);

        /* du = 原方向 (src->dst) 增量, dd = 回包方向增量 */
        uint64_t up = lan_is_src ? du : dd;    /* 客户端上传 */
        uint64_t down = lan_is_src ? dd : du;  /* 客户端下载 */
        TrafCli *tc = traf_find(mac, 1);
        if (!tc) continue;
        tc->tx_tot += up;
        tc->rx_tot += down;
    }
    fclose(f);
    flow_gc();
}

/* ─── 滑动窗口速率 ───────────────────────────────── */

static void push_sample(TrafCli *tc, time_t now) {
    /* 快速判停: 连续 FLAT_SNAP 个 tick 无变化即判停 */
    uint64_t tot = tc->rx_tot + tc->tx_tot;
    if (tot == tc->prev_tot) tc->flat_ticks++;
    else tc->flat_ticks = 0;
    tc->prev_tot = tot;

    tc->head = (tc->head + 1) % TRAF_SLOTS;
    tc->rx_hist[tc->head] = tc->rx_tot;
    tc->tx_hist[tc->head] = tc->tx_tot;
    tc->ts_hist[tc->head] = now;
    if (tc->n < TRAF_SLOTS) tc->n++;

    /* 找窗口内最老的样本 */
    int oldest = tc->head;
    int idx = tc->head;
    for (int i = 1; i < tc->n; i++) {
        idx = (idx - 1 + TRAF_SLOTS) % TRAF_SLOTS;
        if (now - tc->ts_hist[idx] > TRAF_WIN) break;
        oldest = idx;
    }
    double dt = (double)(tc->ts_hist[tc->head] - tc->ts_hist[oldest]);
    if (tc->flat_ticks >= FLAT_SNAP) {
        tc->rx_spd = tc->tx_spd = 0;  /* 快速判停 */
    } else if (dt >= 2 * TRAF_TICK && tc->rx_hist[tc->head] >= tc->rx_hist[oldest]) {
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
    fprintf(f, "# clientstatus traffic | ts=%ld win=%d src=conntrack\\n",
            (long)now, TRAF_WIN);
    fprintf(f, "# MAC|IP|RX_SPD|TX_SPD|RX_TOT|TX_TOT|HW_RX|HW_TX\\n");
    for (int i = 0; i < g_cli_n; i++) {
        TrafCli *tc = &g_cli[i];
        fprintf(f, "%s|%s|%llu|%llu|%llu|%llu|0|0\\n",
                tc->mac, tc->ip[0] ? tc->ip : "-",
                (unsigned long long)(tc->rx_spd + 0.5),
                (unsigned long long)(tc->tx_spd + 0.5),
                (unsigned long long)tc->rx_tot,
                (unsigned long long)tc->tx_tot);
    }
    fclose(f);
    rename(tmp, TRAF_FILE);
}

/* ─── 对外接口 ─────────────────────────────────── */

void traf_init(const char *lan_iface) {
    (void)lan_iface;
    /* 确保 conntrack accounting 开启 */
    FILE *f = fopen(ACCT_PATH, "r");
    if (f) {
        char v[16] = "";
        if (fgets(v, sizeof v, f) && v[0] != '1') {
            fclose(f);
            f = fopen(ACCT_PATH, "w");
            if (f) { fputs("1\\n", f); fclose(f); }
        } else if (f) fclose(f);
    }
    traf_rebuild_map();
}

void traf_tick(void) {
    static time_t last_map;
    time_t now = time(NULL);
    /* 每 30s 重建一次 IP->MAC 映射 */
    if (now - last_map >= 30) {
        traf_rebuild_map();
        last_map = now;
    }
    ct_sample();
    for (int i = 0; i < g_cli_n; i++)
        push_sample(&g_cli[i], now);
    traf_write_file(now);
}
