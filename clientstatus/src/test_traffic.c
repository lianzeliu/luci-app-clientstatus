/* 单元测试: gcc -O2 -Wall -o /tmp/test_traffic test_traffic.c && /tmp/test_traffic */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "traffic.c"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } \
    else { printf("ok: %s\n", msg); } \
} while (0)

/* 喂一段 conntrack 文本 */
static void feed(const char *text) {
    FILE *f = tmpfile();
    fputs(text, f);
    rewind(f);
    sample_conntrack_file(f);
    fclose(f);
}

static TrafCli *find_cli(const char *mac) {
    return traf_find(mac, 0);
}

int main(void) {
    /* ---- 1. 解析器 ---- */
    CtFlow cf;

    /* 标准 IPv4 TCP, 硬件加速流 (无 timeout, 有 [HW_OFFLOAD]) */
    const char *l1 = "ipv4     2 tcp      6 ESTABLISHED src=192.168.1.5 dst=1.2.3.4 "
                     "sport=52344 dport=443 packets=412 bytes=32120 "
                     "src=1.2.3.4 dst=192.168.1.1 sport=443 dport=52344 "
                     "packets=890 bytes=1240500 [HW_OFFLOAD] mark=0";
    CHECK(parse_ct_line(l1, &cf), "parse v4 hw-offload line");
    CHECK(cf.l3 == 4 && cf.proto == 6, "l3/proto");
    CHECK(cf.sport == 52344 && cf.dport == 443, "ports");
    CHECK(cf.up == 32120 && cf.down == 1240500, "bytes up/down");
    CHECK(cf.hw == 1, "hw flag detected");

    /* 普通 CPU 流 (有 timeout) */
    const char *l2 = "ipv4     2 udp     17 170 src=192.168.1.6 dst=8.8.8.8 "
                     "sport=123 dport=53 packets=2 bytes=120 "
                     "src=8.8.8.8 dst=192.168.1.1 sport=53 dport=123 "
                     "packets=2 bytes=200 mark=0";
    CHECK(parse_ct_line(l2, &cf), "parse v4 udp line");
    CHECK(cf.hw == 0 && cf.proto == 17, "no hw flag, proto udp");
    CHECK(cf.up == 120 && cf.down == 200, "udp bytes");

    /* IPv6 */
    const char *l3 = "ipv6     2 tcp      6 ESTABLISHED src=fd00::5 dst=2400::1 "
                     "sport=5000 dport=443 packets=10 bytes=1000 "
                     "src=2400::1 dst=fd00::1 sport=443 dport=5000 "
                     "packets=20 bytes=50000 [HW_OFFLOAD] mark=0";
    CHECK(parse_ct_line(l3, &cf), "parse v6 line");
    CHECK(cf.l3 == 6 && cf.hw == 1, "v6 hw flag");
    CHECK(cf.up == 1000 && cf.down == 50000, "v6 bytes");

    /* 非法行 */
    CHECK(!parse_ct_line("garbage line", &cf), "reject garbage");
    CHECK(!parse_ct_line("ipv4     2 tcp      6", &cf), "reject truncated");

    /* ---- 2. 增量累计 ---- */
    /* 种子映射: 192.168.1.5 -> AA, 192.168.1.6 -> BB, fd00::5 -> CC */
    struct in_addr a4; struct in6_addr a6;
    inet_aton("192.168.1.5", &a4); map_add_v4(a4.s_addr, "AA:BB:CC:DD:EE:01");
    inet_aton("192.168.1.6", &a4); map_add_v4(a4.s_addr, "AA:BB:CC:DD:EE:02");
    inet_pton(AF_INET6, "fd00::5", &a6); map_add_v6(&a6, "AA:BB:CC:DD:EE:03");

    /* tick1: 三流同属一个 tick, 首见只建基线 */
    {
        char t[8192];
        snprintf(t, sizeof t, "%s\n%s\n%s\n", l1, l2, l3);
        feed(t);
    }
    TrafCli *t1 = find_cli("AA:BB:CC:DD:EE:01");
    /* 注意: 首见增量为 0, 不建客户端条目 */
    CHECK(t1 == NULL, "first sight = baseline only (no client entry)");

    /* tick2: 字节增长 -> 只计增量 (l1b 与 l1 同一五元组, l2b 与 l2 同一流) */
    const char *l1b = "ipv4     2 tcp      6 ESTABLISHED src=192.168.1.5 dst=1.2.3.4 "
                      "sport=52344 dport=443 packets=500 bytes=40000 "
                      "src=1.2.3.4 dst=192.168.1.1 sport=443 dport=52344 "
                      "packets=1000 bytes=1500000 [HW_OFFLOAD] mark=0";
    const char *l2b = "ipv4     2 udp     17 170 src=192.168.1.6 dst=8.8.8.8 "
                      "sport=123 dport=53 packets=4 bytes=240 "
                      "src=8.8.8.8 dst=192.168.1.1 sport=53 dport=123 "
                      "packets=4 bytes=400 mark=0";
    {
        char t[8192];
        snprintf(t, sizeof t, "%s\n%s\n%s\n", l1b, l2b, l3);
        feed(t);
    }
    t1 = find_cli("AA:BB:CC:DD:EE:01");
    /* l1->l1b: up 32120->40000 (+7880), down 1240500->1500000 (+259500), 硬件流 */
    CHECK(t1 && t1->tx_tot == 7880 && t1->rx_tot == 259500,
          "tcp hw flow delta counted (tx=7880 rx=259500)");
    CHECK(t1 && t1->hwt_tot == 7880 && t1->hwr_tot == 259500,
          "hw-offload bytes split correctly");
    TrafCli *t2 = find_cli("AA:BB:CC:DD:EE:02");
    CHECK(t2 && t2->tx_tot == 120 && t2->rx_tot == 200,
          "udp flow delta counted (120/200)");
    CHECK(t2 && t2->hwr_tot == 0 && t2->hwt_tot == 0,
          "non-hw flow not in hw counters");

    /* tick3: l2 流消失 -> 累计不回退 */
    {
        char t[8192];
        snprintf(t, sizeof t, "%s\n%s\n", l1b, l3);
        feed(t);
    }
    t2 = find_cli("AA:BB:CC:DD:EE:02");
    CHECK(t2 && t2->tx_tot == 120 && t2->rx_tot == 200,
          "flow aged out, totals don't drop");

    /* tick4: 外部主动连入 (内网 IP 在 dst 端), 与之前累计叠加 */
    const char *l4 = "ipv4     2 tcp      6 100 ESTABLISHED src=9.9.9.9 dst=192.168.1.5 "
                     "sport=443 dport=6000 packets=50 bytes=70000 "
                     "src=192.168.1.5 dst=9.9.9.9 sport=6000 dport=443 "
                     "packets=30 bytes=3000 mark=0";
    const char *l4b = "ipv4     2 tcp      6 100 ESTABLISHED src=9.9.9.9 dst=192.168.1.5 "
                      "sport=443 dport=6000 packets=60 bytes=80000 "
                      "src=192.168.1.5 dst=9.9.9.9 sport=6000 dport=443 "
                      "packets=40 bytes=5000 mark=0";
    {
        char t[4096];
        snprintf(t, sizeof t, "%s\n%s\n%s\n", l1b, l3, l4);
        feed(t); /* l4 基线 */
    }
    {
        char t[4096];
        snprintf(t, sizeof t, "%s\n%s\n%s\n", l1b, l3, l4b);
        feed(t);
    }
    t1 = find_cli("AA:BB:CC:DD:EE:01");
    /* l4->l4b: 原方向 up 70000->80000(+10000, 是内网的下行), 回包 down 3000->5000(+2000, 内网上行) */
    CHECK(t1 && t1->tx_tot == 7880 + 2000 && t1->rx_tot == 259500 + 10000,
          "inbound flow attributed via dst (tx=9880 rx=269500)");

    /* ---- 3. 滑动窗口速率 (8s 窗口, 1s 采样, 硬件同步约 3s 一次) ---- */
    TrafCli tc;
    memset(&tc, 0, sizeof tc);
    /* 模拟 24 秒: 每 3 秒同步一次硬件计数, 每次 +30000 (真实速率 10000 B/s),
       1 秒采样一次 (部分 tick 无变化, 还原抖动) */
    time_t base = 1000000;
    for (int s = 0; s <= 24; s++) {
        tc.rx_tot = (uint64_t)(s / 3) * 30000;
        push_sample(&tc, base + s);
        /* 预热后全程不能出现毛刺 (>=15000) 或异常归零 */
        if (s >= 8) {
            char msg[96];
            snprintf(msg, sizeof msg, "t=%ds rate sane (%.0f)", s, tc.rx_spd);
            CHECK(tc.rx_spd > 5000 && tc.rx_spd < 15000, msg);
        }
    }
    /* 稳定后速率应在 10000 附近 */
    CHECK(tc.rx_spd > 8000 && tc.rx_spd < 14000, "windowed rate ~10000 B/s");

    /* ---- 4. 快速判停: 连续 6 tick 无变化 -> 速率置 0 ---- */
    {
        TrafCli t2;
        memset(&t2, 0, sizeof t2);
        time_t b2 = 2000000;
        /* 先跑 10 秒流量 */
        for (int s = 0; s <= 10; s++) {
            t2.rx_tot = (uint64_t)(s / 3) * 30000;
            push_sample(&t2, b2 + s);
        }
        CHECK(t2.rx_spd > 5000, "traffic flowing, speed > 0");
        /* 停流: 累计冻结 */
        uint64_t frozen = t2.rx_tot;
        int snapped_at = -1;
        for (int s = 11; s <= 20; s++) {
            t2.rx_tot = frozen;
            push_sample(&t2, b2 + s);
            if (t2.rx_spd == 0 && snapped_at < 0) snapped_at = s;
        }
        CHECK(snapped_at > 0 && snapped_at <= 16,
              "flat 6 ticks -> snap to 0 (no 8s window lag)");
        /* 恢复流量后立刻回升 */
        t2.rx_tot = frozen + 50000;
        push_sample(&t2, b2 + 21);
        CHECK(t2.rx_spd > 0, "traffic resumes, speed recovers immediately");
    }

    printf(fails ? "\n%d FAILURES\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
