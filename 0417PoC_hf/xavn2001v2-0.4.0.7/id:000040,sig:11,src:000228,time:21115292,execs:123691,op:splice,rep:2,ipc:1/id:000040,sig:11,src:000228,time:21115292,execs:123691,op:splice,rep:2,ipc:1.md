漏洞名称：
Netgear XAVN2001v2 wl_enable_ssid_broadcast参数缺失导致空指针解引用漏洞（样本id:000040）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向/apply.cgi发送构造的POST请求，使程序在无线配置处理路径中读取缺失的`wl_enable_ssid_broadcast`字段，并将空指针直接作为参数传给nvram_set，最终导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理/apply.cgi请求时，`submit_flag=wlan`会使程序进入无线配置相关处理函数。当前样本中，程序在0x439154附近的无线配置流程中，调用cgi_value读取`wl_enable_ssid_broadcast`字段。由于该字段在请求中缺失，cgi_value返回NULL。随后程序在0x4391b0将该返回值放入a1，并在0x4391c0直接调用nvram_set，将NULL作为`wla_endis_ssid_broadcast`对应的值写入NVRAM，最终触发空指针崩溃。

攻击者可以远程发起攻击，通过发送`submit_flag=wlan`且缺失`wl_enable_ssid_broadcast`字段的POST请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中保留了trace、日志以及相关分析材料，能够看到无线配置处理函数中从cgi_value到nvram_set的完整崩溃链路。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/apply.cgi发送POST请求，并通过`submit_flag=wlan`使程序进入无线配置处理路径。程序随后在相关配置函数中逐项读取无线参数。
![alt text](image.png)

第二步。处理流程在0x4391a0调用cgi_value读取`wl_enable_ssid_broadcast`，但当前样本中该字段缺失，因此返回NULL。程序没有进行判空，而是继续把返回值准备为nvram_set的第二个参数。
![alt text](image-1.png)

第三步。0x4391c0处的nvram_set调用接收到空指针参数后触发SIGSEGV。trace与容器日志都显示`si_addr=NULL`，说明这不是元数据误判，而是无线配置路径中的真实空指针解引用漏洞。
![alt text](image-2.png)

相关问题代码：

0x439154
