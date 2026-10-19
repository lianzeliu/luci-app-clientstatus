/*
 * traffic.h — 流量统计引擎 (conntrack 单数据源重写版)
 *
 * 设计要点:
 *  1. 单数据源为 /proc/net/nf_conntrack: 解析 ALL 流 (不再只限 [HW_OFFLOAD])。
 *     前提 net.netfilter.nf_conntrack_acct=1 (daemon 启动时自动开启),
 *     此时软件转发和硬件加速流都有 bytes= 计数, 无需 nft, 无重叠重复计数。
 *  2. per-flow (5 元组) 基线: 只计增量; 新流首见永远先建基线 (init 标记),
 *     不把累计值当增量, 免疫 GC 重现导致的虚高 spike。
 *  3. IP->MAC 经 ARP/neighbor 表归属; 两端都是 LAN 的流跳过 (只计 WAN)。
 *  4. 实时速率: 1s 采样, 3s 滑动窗口, 连续 2 tick 无变化直接判停为 0。
 *     窗口短 + 判停快, 空闲时不拖尾。
 */
#ifndef CLIENTSTATUS_TRAFFIC_H
#define CLIENTSTATUS_TRAFFIC_H

/* 采样间隔(秒) */
#define TRAF_TICK 1

/* daemon 启动时调用一次 */
void traf_init(const char *lan_iface);

/* 客户端发现完成后刷新 IP->MAC 映射 */
void traf_rebuild_map(void);

/* 每秒调用一次: 采样 + 计算 + 写文件 */
void traf_tick(void);

#endif
