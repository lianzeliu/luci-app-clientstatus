/*
 * traffic.h — MTK 硬件加速感知的流量统计引擎
 *
 * 设计要点:
 *  1. 主数据源为 iptables mangle 表的每 IP 计数器 (wrtbwmon 原理):
 *     每个 LAN IP 建 -s/-d 两条 RETURN 规则挂在 FORWARD 链下,
 *     每秒 iptables -Z 原子读出精确增量, 无需 per-flow 基线管理,
 *     不受 conntrack 同步抖动影响; IP->MAC 经 ARP 表归属。
 *  2. 补充数据源为 conntrack [HW_OFFLOAD] 流: 走 PPE 硬件的包
 *     不经过 netfilter, iptables 看不到, 用 per-flow 基线跟踪
 *     内核同步回来的硬件增量, 与 iptables 互补不重叠。
 *     (需 net.netfilter.nf_conntrack_acct=1, daemon 启动时自动尝试开启)
 *  3. 实时速率用 8 秒滑动窗口计算, 连续 6 秒无变化直接判停。
 *  4. 本版本无 WiFi: 不依赖 iwinfo。
 */
#ifndef CLIENTSTATUS_TRAFFIC_H
#define CLIENTSTATUS_TRAFFIC_H

/* 采样间隔(秒): 硬件计数约 3s 同步一次, 1s 采样保证不漏掉任何一次同步 */
#define TRAF_TICK 1

/* daemon 启动时调用一次 */
void traf_init(const char *lan_iface);

/* 客户端发现完成后刷新 IP->MAC 映射 */
void traf_rebuild_map(void);

/* 每 2 秒调用一次: 采样 + 计算 + 写文件 */
void traf_tick(void);

#endif
