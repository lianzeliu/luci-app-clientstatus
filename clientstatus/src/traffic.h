/*
 * traffic.h — MTK 硬件加速感知的流量统计引擎
 *
 * 设计要点:
 *  1. 以 /proc/net/nf_conntrack 的 bytes= 为唯一可信数据源。
 *     内核会把 PPE 硬件流表的 MIB 计数器定期同步回 conntrack accounting
 *     (flowtable counter + FLOW_CLS_STATS), 所以硬件加速走掉的流量
 *     这里一样能数到, 前提是 net.netfilter.nf_conntrack_acct=1。
 *  2. 逐流维护基线做增量, 流老化只丢 key 不丢累计值。
 *  3. 实时速率用 10 秒滑动窗口计算 (硬件计数约 3 秒同步一次,
 *     10 秒覆盖 3 次, 既免疫毛刺又保证启停反应)。
 *  4. 本版本无 WiFi: 纯 conntrack, 不依赖 iwinfo。
 */
#ifndef CLIENTSTATUS_TRAFFIC_H
#define CLIENTSTATUS_TRAFFIC_H

/* daemon 启动时调用一次 */
void traf_init(const char *lan_iface);

/* 客户端发现完成后刷新 IP->MAC 映射 */
void traf_rebuild_map(void);

/* 每 2 秒调用一次: 采样 + 计算 + 写文件 */
void traf_tick(void);

#endif
