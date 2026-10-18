LuCI Client Status 是一个 OpenWrt LuCI 软件包，用于实时监控和管理局域网客户端。通过多种数据源检测设备在线/离线状态，并提供简洁的 Web 界面进行 ACL 控制。

依赖：
由于使用的Lua系统，如果安装完系统菜单没有显示该插件，请安装安装luci-compat。

功能特性

多源检测：Conntrack 连接追踪、ARP 表、DHCP 租约、WiFi 关联列表、ICMP Ping

设备识别：自动区分有线/无线连接，显示 SSID

ACL 控制：在界面上直接拦截/放行客户端

自定义主机名：编辑并持久化客户端显示名称

显示客户端实时网速，基于wifi流量及连接的流量统计，不是专业的测速，不保证绝对准确性，只做参考。

流量统计引擎（v1.1.0 重写，针对 MTK 硬件加速优化，无 WiFi 版）：
- 数据源为内核 conntrack 的 bytes= 累计值，PPE 硬件流表计数器约每 3 秒同步回来
  （flowtable GC 每秒跑，节流条件为 timeout 的 10%，TCP/UDP offload_timeout=30s），
  因此硬件加速走掉的流量也能统计到（需 net.netfilter.nf_conntrack_acct=1，
  daemon 启动时自动尝试开启）；
- 逐流维护基线只计增量，流老化不丢累计值；daemon 每 1 秒采样，
  实时速率按 8 秒滑动窗口计算（覆盖约 2-3 次硬件同步），
  连续 6 秒无变化直接判停，启停反应在数秒内；
- 每个客户端单独累计硬件加速字节（/tmp/clientstatus.traffic 的 HW_RX/HW_TX 列）。

智能刷新：基于信号的心跳机制——前端活跃时 自定义轮询时间，关闭后自动降频至300 秒

暗色模式：跟随系统偏好自动切换

响应式布局：桌面端与移动端均适配


使用方法：

1.编译安装，完整的APK(OPKG)格式支持直接在各个架构平台编译。
	
	1.1 编译版本顺便把shell换成了C代码，这样执行效率及资源占用相对低一点，代码是xiaomi-Mimo重构的，不保证代码有严重bug，有兴趣的可以提交新的代码。

2.直接安装：不分架构，都可以直接安装

	2.1 直接安装版本所有代码全平台通用，可以直接下载，安装界面输入1即安装，2是卸载。
在控制台运行代码，即可完成安装！

curl -fsSL https://raw.githubusercontent.com/migee99/luci-app-clientstatus/main/install.sh | sh

或者

wget -qO- https://raw.githubusercontent.com/migee99/luci-app-clientstatus/main/install.sh | sh

安装完成后请退出登陆web页面，重新进入即可！

特别说明：

本插件的禁止联网功能只是禁止客户端连接互联网，不能断开wifi连接。

本插件有线客户端的实时网速只显示客户端的互联网出口的网速，不包含局域网内互传的流量。

因浏览器及系统字体原因，小屏设备显示可能不完美。
