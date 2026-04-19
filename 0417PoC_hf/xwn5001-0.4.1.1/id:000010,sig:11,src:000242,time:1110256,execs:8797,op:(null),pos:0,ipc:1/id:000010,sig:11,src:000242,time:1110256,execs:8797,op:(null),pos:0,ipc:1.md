http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 0x00437ec0 空指针解引用漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个 `空指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。config_wladv_plc 从 CGI 读取 wl_enable_LED 后未判空，直接把返回指针送入 strcmp，当请求里缺失该字段时触发空指针解引用。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。程序在 `uhttpd fcn.00437e0c 0x00437e7c (jalr cgi_value，key="wl_enable_LED") 0x00437e7c` 处对攻击者可控输入完成读取、解析或传递，并最终在 `uhttpd fcn.00437e0c 0x00437ec0 (jalr strcmp，危险实参在 0x00437ebc: move a0, s1) 0x00437ec0` 处进入危险操作，最终导致进程崩溃并造成拒绝服务。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。uhttpd 在 0x40b9a8 读取 submit_flag，得到 wlan_adv_plc，并在 0x40ba30 经分发表调用 0x437e0c

第二步。fcn.00437e0c 在 0x437e7c 调 cgi_value("wl_enable_LED", ...)，由于请求体没有该字段，v0=NULL，随后在 0x437e90 保存到 s1

第三步。fcn.00437e0c 在 0x437ec0 调 strcmp(s1, "off")，其中 a0=s1=NULL，随即在 trace 末尾触发 SIGSEGV

相关问题代码：

0x00437ec0
