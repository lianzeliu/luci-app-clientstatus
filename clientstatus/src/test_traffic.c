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
    /* ---- 1. nft 命名计数器映射 ---- */
    /* 手动注入映射 (模拟 nft_add_ip 成功后的状态) */
    NftCounter *n1 = &g_nft[g_nft_n++];
    strcpy(n1->name, "u_v4_1"); mac_copy(n1->mac, "AA:BB:CC:DD:EE:01");
    n1->is_up = 1; n1->handle = 100;
    NftCounter *n2 = &g_nft[g_nft_n++];
    strcpy(n2->name, "d_v4_1"); mac_copy(n2->mac, "AA:BB:CC:DD:EE:01");
    n2->is_up = 0; n2->handle = 101;
    NftCounter *n3 = &g_nft[g_nft_n++];
    strcpy(n3->name, "u_v6_5"); mac_copy(n3->mac, "AA:BB:CC:DD:EE:03");
    n3->is_up = 1; n3->handle = 102;
    CHECK(nft_find("u_v4_1") == n1, "nft_find by name");

    /* ---- 2. nft --json 输出解析 ---- */
    const char *mock_json =
        "{\"nftables\": ["
        "{\"counter\": {\"family\": \"inet\", \"table\": \"cs_traffic\", "
        "\"name\": \"u_v4_1\", \"packets\": 10, \"bytes\": 10000}}, "
        "{\"counter\": {\"family\": \"inet\", \"table\": \"cs_traffic\", "
        "\"name\": \"d_v4_1\", \"packets\": 50, \"bytes\": 50000}}, "
        "{\"counter\": {\"family\": \"inet\", \"table\": \"cs_traffic\", "
        "\"name\": \"u_v6_5\", \"packets\": 7, \"bytes\": 70000}}, "
        "{\"counter\": {\"family\": \"inet\", \"table\": \"cs_traffic\", "
        "\"name\": \"d_v4_999\", \"packets\": 1, \"bytes\": 999}}"
        "]}";
    nft_parse_counters(mock_json);
    TrafCli *t1 = traf_find("AA:BB:CC:DD:EE:01", 0);
    TrafCli *t3 = traf_find("AA:BB:CC:DD:EE:03", 0);
    CHECK(t1 && t1->tx_tot == 10000 && t1->rx_tot == 50000,
          "nft JSON: u_v4_1 tx=10000, d_v4_1 rx=50000");
    CHECK(t3 && t3->tx_tot == 70000,
          "nft JSON: u_v6_5 tx=70000");
    CHECK(t1->tx_tot != 10999, "unknown counter d_v4_999 ignored");

    /* ---- 2b. 差值法: 第二次采样只计增量, reset 失效也不暴涨 ---- */
    const char *mock_json2 =
        "{\"nftables\": ["
        "{\"counter\": {\"name\": \"u_v4_1\", \"bytes\": 15000}}, "
        "{\"counter\": {\"name\": \"d_v4_1\", \"bytes\": 60000}}"
        "]}";
    nft_parse_counters(mock_json2);
    CHECK(t1->tx_tot == 15000 && t1->rx_tot == 60000,
          "nft delta: second sample adds only 5000/10000");
    /* 模拟计数器回绕/重置: 值变小则记 0, 不暴涨 */
    const char *mock_json3 =
        "{\"nftables\": [{\"counter\": {\"name\": \"u_v4_1\", \"bytes\": 100}}]}";
    nft_parse_counters(mock_json3);
    CHECK(t1->tx_tot == 15000, "nft reset/wrap: no spike on counter decrease");

    /* ---- 3. conntrack [HW_OFFLOAD] 补充 ---- */
    const char *hwline =
        "ipv4     2 tcp      6 431982 ESTABLISHED src=192.168.1.2 dst=1.2.3.4 "
        "sport=12345 dport=443 packets=10 bytes=10000 src=1.2.3.4 dst=192.168.1.2 "
        "sport=443 dport=12345 packets=200 bytes=200000 [HW_OFFLOAD] mark=0 use=1\n";
    /* 先建映射 (192.168.1.2 -> :01) */
    struct in_addr a;
    inet_aton("192.168.1.2", &a);
    map_add_v4(a.s_addr, "AA:BB:CC:DD:EE:01");
    CtFlow cf;
    CHECK(parse_ct_line(hwline, &cf) == 1, "parse HW flow");
    CHECK(cf.up == 10000 && cf.down == 200000, "HW flow bytes parsed");
    const char *plainline =
        "ipv4     2 tcp      6 431982 ESTABLISHED src=192.168.1.2 dst=1.2.3.4 "
        "sport=12345 dport=443 packets=10 bytes=10000 src=1.2.3.4 dst=192.168.1.2 "
        "sport=443 dport=12345 packets=200 bytes=200000 [ASSURED] mark=0 use=1\n";
    CHECK(parse_ct_line(plainline, &cf) == 0, "non-HW flow skipped");

    /* ---- 4. 滑动窗口速率 (8s) ---- */
    TrafCli tc;
    memset(&tc, 0, sizeof tc);
    time_t base = 1000000;
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

    /* ---- 5. 快速判停 ---- */
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
