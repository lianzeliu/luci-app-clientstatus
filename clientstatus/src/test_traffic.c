/* 流量引擎单测: gcc -O2 -Wall -o /tmp/test_traffic test_traffic.c && /tmp/test_traffic */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "traffic.c"

static int fails;
#define CHECK(cond, msg) do { \
    if (cond) printf("ok: %s\n", msg); \
    else { printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } \
} while (0)

int main(void) {
    /* ---- 1. IP->MAC 映射 ---- */
    struct in_addr a;
    inet_aton("192.168.1.2", &a);
    map_add_v4(a.s_addr, "AA:BB:CC:DD:EE:01");
    inet_aton("192.168.1.3", &a);
    map_add_v4(a.s_addr, "AA:BB:CC:DD:EE:02");
    CHECK(map_lookup_v4(a.s_addr) != NULL, "map v4 lookup");

    /* ---- 2. iptables -Z 输出解析 (wrtbwmon 原理) ---- */
    /* 模拟: .2 上传 10000 字节, 下载 50000 字节; .3 上传 2000 */
    const char *mock =
        "Chain CS_TRAFFIC (1 references)\n"
        " pkts bytes target     prot opt in     out     source               destination\n"
        "   10  10000 RETURN     all  --  *      *       192.168.1.2          0.0.0.0/0\n"
        "   50  50000 RETURN     all  --  *      *       0.0.0.0/0            192.168.1.2\n"
        "    2   2000 RETURN     all  --  *      *       192.168.1.3          0.0.0.0/0\n"
        "    0      0 RETURN     all  --  *      *       0.0.0.0/0            192.168.1.3\n";
    FILE *mf = fmemopen((void *)mock, strlen(mock), "r");
    ipt_sample_fp(mf, 0);
    fclose(mf);
    TrafCli *t1 = traf_find("AA:BB:CC:DD:EE:01", 0);
    TrafCli *t2 = traf_find("AA:BB:CC:DD:EE:02", 0);
    CHECK(t1 && t1->tx_tot == 10000 && t1->rx_tot == 50000,
          "iptables: .2 tx=10000 rx=50000");
    CHECK(t2 && t2->tx_tot == 2000 && t2->rx_tot == 0,
          "iptables: .3 tx=2000 rx=0");
    /* 未知 IP 不建客户端 */
    int n_before = g_cli_n;
    const char *mock2 =
        "    5   9999 RETURN     all  --  *      *       192.168.1.99         0.0.0.0/0\n";
    mf = fmemopen((void *)mock2, strlen(mock2), "r");
    ipt_sample_fp(mf, 0);
    fclose(mf);
    CHECK(g_cli_n == n_before, "unknown IP ignored");

    /* ---- 3. IPv6 iptables 解析 ---- */
    struct in6_addr a6;
    inet_pton(AF_INET6, "fd00::5", &a6);
    map_add_v6(&a6, "AA:BB:CC:DD:EE:03");
    const char *mock6 =
        "Chain CS_TRAFFIC6 (1 references)\n"
        " pkts bytes target     prot opt in     out     source               destination\n"
        "    7   70000 RETURN     all  --  *      *       ::/0                 fd00::5\n";
    mf = fmemopen((void *)mock6, strlen(mock6), "r");
    ipt_sample_fp(mf, 1);
    fclose(mf);
    TrafCli *t3 = traf_find("AA:BB:CC:DD:EE:03", 0);
    CHECK(t3 && t3->rx_tot == 70000, "ip6tables: fd00::5 rx=70000");

    /* ---- 4. conntrack [HW_OFFLOAD] 补充 ---- */
    const char *hwline =
        "ipv4     2 tcp      6 431982 ESTABLISHED src=192.168.1.2 dst=1.2.3.4 "
        "sport=12345 dport=443 packets=10 bytes=10000 src=1.2.3.4 dst=192.168.1.2 "
        "sport=443 dport=12345 packets=200 bytes=200000 [HW_OFFLOAD] mark=0 use=1\n";
    CtFlow cf;
    CHECK(parse_ct_line(hwline, &cf) == 1, "parse HW flow");
    CHECK(cf.up == 10000 && cf.down == 200000, "HW flow bytes parsed");
    /* 非 HW 流应被拒绝 */
    const char *plainline =
        "ipv4     2 tcp      6 431982 ESTABLISHED src=192.168.1.2 dst=1.2.3.4 "
        "sport=12345 dport=443 packets=10 bytes=10000 src=1.2.3.4 dst=192.168.1.2 "
        "sport=443 dport=12345 packets=200 bytes=200000 [ASSURED] mark=0 use=1\n";
    CHECK(parse_ct_line(plainline, &cf) == 0, "non-HW flow skipped");

    /* ---- 5. 滑动窗口速率 (8s) ---- */
    TrafCli tc;
    memset(&tc, 0, sizeof tc);
    time_t base = 1000000;
    /* 每秒 +10000 (模拟 iptables 精确增量), 持续 20s */
    for (int s = 0; s <= 20; s++) {
        tc.rx_tot = (uint64_t)s * 10000;
        push_sample(&tc, base + s);
        if (s >= 8) {
            char msg[96];
            snprintf(msg, sizeof msg, "t=%ds rate sane (%.0f)", s, tc.rx_spd);
            CHECK(tc.rx_spd > 8000 && tc.rx_spd < 12000, msg);
        }
    }
    CHECK(tc.rx_spd > 9000 && tc.rx_spd < 11000, "windowed rate ~10000 B/s");

    /* ---- 6. 快速判停 ---- */
    {
        TrafCli t2c;
        memset(&t2c, 0, sizeof t2c);
        time_t b2 = 2000000;
        for (int s = 0; s <= 10; s++) {
            t2c.rx_tot = (uint64_t)s * 10000;
            push_sample(&t2c, b2 + s);
        }
        CHECK(t2c.rx_spd > 5000, "traffic flowing, speed > 0");
        uint64_t frozen = t2c.rx_tot;
        int snapped_at = -1;
        for (int s = 11; s <= 20; s++) {
            t2c.rx_tot = frozen;
            push_sample(&t2c, b2 + s);
            if (t2c.rx_spd == 0 && snapped_at < 0) snapped_at = s;
        }
        CHECK(snapped_at > 0 && snapped_at <= 16, "flat 6 ticks -> snap to 0");
        t2c.rx_tot = frozen + 50000;
        push_sample(&t2c, b2 + 21);
        CHECK(t2c.rx_spd > 0, "traffic resumes, speed recovers");
    }

    if (fails == 0) printf("\nALL PASS\n");
    else printf("\n%d FAILURES\n", fails);
    return fails != 0;
}
