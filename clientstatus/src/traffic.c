/*
 * traffic.c — 流量统计引擎 (nftables 命名计数器 + MTK 硬件加速补充)
 *
 * 主数据源: nftables 命名计数器。
 *   - 表 inet cs_traffic, base chain 直接挂 forward hook
 *     (priority -151, 在 mangle 之前, 与 iptables-nft 一致)。
 *   - 每个 LAN IP 建两条规则: ip saddr (上传) / ip daddr (下载),
 *     每条带独立命名 counter (u_v4_N / d_v4_N)。
 *   - 每秒 nft --json 读出精确增量并重置, 无需 per-flow 基线管理,
 *     不受 conntrack 同步抖动影响, JSON 解析比 iptables 文本更可靠。
 *   - IP->MAC 经 ARP 表归属。
 * 补充数据源: conntrack [HW_OFFLOAD] 流。
 *   - 走 PPE 硬件的包不经过 netfilter, nft 看不到;
 *     用 per-flow 基线跟踪内核同步回来的硬件增量, 与 nft 互补不重叠。
 *   - 同样只计 WAN (两端都是 LAN IP 的流跳过)。
 * 速率: 1s 采样, 8s 滑动窗口 + 连续 6s 无变化直接判停。
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

#define TRAF_WIN      3    /* 速率滑动窗口(秒): 3s, 跟 wrtbwmon 短间隔一致 */
#define TRAF_SLOTS    5    /* 环形槽位数 >= WIN/TICK + 2 */
#define FLAT_SNAP     2    /* 连续 N 个 tick 累计不变 -> 直接判停, 速率置 0 */
#define MAX_CLI       512
#define FLOW_BUCKETS  4096
#define MAX_LINE      4096

#define NFT_TABLE   "cs_traffic"
#define NFT_CHAIN   "cs_fwd"
#define NFT_SYNC_EVERY 10   /* 每 N 个 tick 从 ARP 同步一次规则 */

/* 执行 shell 命令, 忽略返回值 */
static void run(const char *cmd) {
    int r = system(cmd);
    (void)r;
}

/* WAN 口 (从默认路由探测) */
static char g_wan4[32], g_wan6[32];

static void detect_wan_one(const char *cmd, char *out, size_t outlen) {
    out[0] = '\0';
    FILE *f = popen(cmd, "r");
    if (!f) return;
    char line[256];
    if (fgets(line, sizeof line, f)) {
        char *p = strstr(line, " dev ");
        if (p) {
            p += 5;
            size_t i = 0;
            while (*p && !isspace((unsigned char)*p) && i + 1 < outlen)
                out[i++] = *p++;
            out[i] = '\0';
        }
    }
    pclose(f);
}

static void detect_wan(void) {
    detect_wan_one("ip -4 route show default 2>/dev/null", g_wan4, sizeof g_wan4);
    detect_wan_one("ip -6 route show default 2>/dev/null", g_wan6, sizeof g_wan6);
}

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

/* 安全拷贝 MAC (17 字符 + NUL, 截断保护) */
static void mac_copy(char *dst, const char *src) {
    size_t n = strlen(src);
    if (n >= ML) n = ML - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void map_add_v4(uint32_t v4, const char *mac) {
    if (g_map_n >= 1024 || !valid_mac(mac)) return;
    for (int i = 0; i < g_map_n; i++)
        if (!g_map[i].v6 && g_map[i].v4 == v4) return;
    g_map[g_map_n].v6 = 0;
    g_map[g_map_n].v4 = v4;
    mac_copy(g_map[g_map_n].mac, mac);
    upper(g_map[g_map_n].mac);
    g_map_n++;
}

static void map_add_v6(const struct in6_addr *a6, const char *mac) {
    if (g_map_n >= 1024 || !valid_mac(mac)) return;
    for (int i = 0; i < g_map_n; i++)
        if (g_map[i].v6 && memcmp(&g_map[i].a6, a6, 16) == 0) return;
    g_map[g_map_n].v6 = 1;
    g_map[g_map_n].a6 = *a6;
    mac_copy(g_map[g_map_n].mac, mac);
    upper(g_map[g_map_n].mac);
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

/* 从 dhcp.leases / arp / v6 neigh 重建映射, 并同步 nft 规则 */
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

/* ─── 客户端累计 ─────────────────────────────────── */

typedef struct {
    char mac[ML];
    char ip[64];
    double rx_spd, tx_spd;
    uint64_t rx_tot, tx_tot;
    uint64_t hwr_tot, hwt_tot;  /* 硬件累计 (兼容, 未用) */
    uint64_t prev_tot;
    uint64_t last_rx, last_tx;  /* 上 tick 的 rx_tot/tx_tot, 算增量用 */
    int flat_ticks;
    int ema_init;  /* EMA 是否已初始化 */
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
    return tc;
}


/* ─── conntrack [HW_OFFLOAD] 补充 ─────────────────── */

typedef struct {
    uint8_t l3;
    uint8_t proto;
    uint8_t saddr[16], daddr[16];
    uint16_t sport, dport;
    uint64_t up, down;
} CtFlow;

static int parse_ct_line(const char *line, CtFlow *cf) {
    memset(cf, 0, sizeof *cf);
    if (strncmp(line, "ipv4", 4) == 0) cf->l3 = 4;
    else if (strncmp(line, "ipv6", 4) == 0) cf->l3 = 6;
    else return 0;
    if (!strstr(line, "[HW_OFFLOAD]")) return 0;  /* 只处理硬件流 */

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
        } else if (strncmp(t, "bytes=", 6) == 0) {
            uint64_t b = strtoull(t + 6, NULL, 10);
            if (nbytes == 0) cf->up = b; else cf->down = b;
            nbytes++;
        }
        tok++;
    }
    if (nsrc < 2 || ndst < 2) return 0;

    if (cf->l3 == 4) {
        struct in_addr a;
        if (!inet_aton(saddr_s, &a)) return 0;
        memcpy(cf->saddr, &a.s_addr, 4);
        if (!inet_aton(daddr_s, &a)) return 0;
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

/* per-flow 基线 (只跟踪 HW 流) */
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

/* 内网 IP 归属: 先 src 后 dst */
static const char *hw_ipmac(const CtFlow *cf, int use_src, int *is_v6,
                            uint32_t *v4, struct in6_addr *a6) {
    const uint8_t *ip = use_src ? cf->saddr : cf->daddr;
    if (cf->l3 == 4) {
        uint32_t a;
        memcpy(&a, ip, 4);
        /* 排除回环/组播 */
        uint32_t host = ntohl(a);
        if ((host >> 24) == 127 || (host >> 28) == 0xE) return NULL;
        *is_v6 = 0; *v4 = a;
        return map_lookup_v4(a);
    } else {
        struct in6_addr ia6;
        memcpy(&ia6, ip, 16);
        if (IN6_IS_ADDR_LOOPBACK(&ia6) || IN6_IS_ADDR_MULTICAST(&ia6)) return NULL;
        *is_v6 = 1; *a6 = ia6;
        return map_lookup_v6(&ia6);
    }
}

static void hw_sample(void) {
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

        int is_v6; uint32_t v4; struct in6_addr a6;
        int is_v6d; uint32_t v4d; struct in6_addr a6d;
        const char *mac_s = hw_ipmac(&cf, 1, &is_v6, &v4, &a6);
        const char *mac_d = hw_ipmac(&cf, 0, &is_v6d, &v4d, &a6d);
        if (mac_s && mac_d) continue;  /* LAN 互访, 只计 WAN */
        const char *mac = mac_s ? mac_s : mac_d;
        int lan_is_src = (mac_s != NULL);
        if (!mac) continue;

        uint64_t up = lan_is_src ? du : dd;
        uint64_t down = lan_is_src ? dd : du;
        TrafCli *tc = traf_find(mac, 1);
        if (!tc) continue;
        tc->tx_tot += up;   tc->rx_tot += down;
        tc->hwt_tot += up;  tc->hwr_tot += down;
    }
    fclose(f);
    flow_gc();
}

/* ─── EMA 平滑速率 + 落盘 ───────────────────────────── */

#define EMA_ALPHA 0.4  /* EMA 系数: 0.4 ≈ 2-3 秒有效窗口, 响应快且平滑 */

static void push_sample(TrafCli *tc, time_t now) {
    (void)now;
    /* 快速判停: 连续 2 个 tick 无变化即判停 */
    uint64_t tot = tc->rx_tot + tc->tx_tot;
    if (tot == tc->prev_tot) {
        tc->flat_ticks++;
    } else {
        tc->flat_ticks = 0;
    }
    tc->prev_tot = tot;

    if (tc->flat_ticks >= 2) {
        tc->rx_spd = tc->tx_spd = 0;
        tc->ema_init = 0;  /* 下次从零启动 */
        return;
    }

    /* 本 tick 增量 */
    uint64_t rx_delta = (tc->rx_tot >= tc->last_rx) ? (tc->rx_tot - tc->last_rx) : 0;
    uint64_t tx_delta = (tc->tx_tot >= tc->last_tx) ? (tc->tx_tot - tc->last_tx) : 0;
    tc->last_rx = tc->rx_tot;
    tc->last_tx = tc->tx_tot;

    /* sanity: 单 tick 超过 500MB 视为异常 */
    if (rx_delta > 500ULL*1024*1024) rx_delta = 0;
    if (tx_delta > 500ULL*1024*1024) tx_delta = 0;

    double inst_rx = (double)rx_delta;
    double inst_tx = (double)tx_delta;

    if (!tc->ema_init) {
        tc->rx_spd = inst_rx;
        tc->tx_spd = inst_tx;
        tc->ema_init = 1;
    } else {
        tc->rx_spd = EMA_ALPHA * inst_rx + (1 - EMA_ALPHA) * tc->rx_spd;
        tc->tx_spd = EMA_ALPHA * inst_tx + (1 - EMA_ALPHA) * tc->tx_spd;
    }

    /* 小流量抑制: < 1KB/s 视为 0 */
    if (tc->rx_spd < 1024) tc->rx_spd = 0;
    if (tc->tx_spd < 1024) tc->tx_spd = 0;
}

static void traf_write_file(time_t now) {
    char tmp[64];
    snprintf(tmp, sizeof tmp, "%s.tmp", TRAF_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "# clientstatus traffic | ts=%ld src=conntrack-hw-only ema=0.4\n",
            (long)now);
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

void traf_init(const char *lan_iface) {
    if (lan_iface && lan_iface[0]) {
        strncpy(g_lan, lan_iface, sizeof g_lan - 1);
        g_lan[sizeof g_lan - 1] = '\0';
    }
    /* 确保 nf_conntrack_acct 开启 (HW 补充需要) */
    FILE *f = fopen(ACCT_PATH, "r");
    if (f) {
        char v[8] = "";
        if (fgets(v, sizeof v, f) && v[0] != '1') {
            fclose(f);
            f = fopen(ACCT_PATH, "w");
            if (f) { fputs("1\n", f); fclose(f); f = NULL; }
        }
        if (f) fclose(f);
    }
    /* 检查 firewall4 flowtable 是否带 counter (HW 流量同步需要) */
    {
        FILE *pf = popen("nft list flowtables 2>/dev/null", "r");
        int has_ctr = 0;
        if (pf) {
            char lb[512];
            while (fgets(lb, sizeof lb, pf))
                if (strstr(lb, "counter")) { has_ctr = 1; break; }
            pclose(pf);
        }
        /* 结果写入状态文件供诊断, 不阻断运行 */
        FILE *sf = fopen("/tmp/clientstatus.flowtable", "w");
        if (sf) {
            fprintf(sf, "flowtable_counter=%d\n", has_ctr);
            fclose(sf);
        }
    }
    /* 确保 conntrack accounting 开启 (硬件流需要) */
    system("sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null");
    traf_rebuild_map();
}

void traf_tick(void) {
    static int tick = 0;
    time_t now = time(NULL);
    tick++;

    hw_sample();  /* 纯 conntrack [HW_OFFLOAD], 不用 iptables */

    if (tick % 10 == 0)
        traf_rebuild_map();  /* 刷新 IP->MAC 映射 */

    for (int i = 0; i < g_cli_n; i++)
        push_sample(&g_cli[i], now);

    traf_write_file(now);
}
