http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 0x438e64 空指针解引用漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个 `空指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。wlan_g1_a1 处理函数从 CGI 参数中读取 wlg_guest_endis_wireless_isolation 后，未检查返回值是否为 NULL，就直接把它作为第二实参传给 nvram_set，导致空指针解引用崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。程序在 `uhttpd 0x438e64 0x439058 (cgi_value("wlg_guest_endis_wireless_isolation", req, env)) 0x438e64` 处对攻击者可控输入完成读取、解析或传递，并最终在 `uhttpd 0x438e64 0x43907c (jalr -> nvram_set("endis_wlg_guest_wireless_isolation", v0)) 0x438e64` 处进入危险操作，最终导致进程崩溃并造成拒绝服务。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。POST /apply.cgi? 请求进入 uhttpd，cgi_setobject(0x40b95c) 通过 cgi_value("submit_flag", ...) 读到 body.submit_flag=wlan_g1_a1。

第二步。cgi_setobject 在对象表 0x4718b0 命中表项 wlan_g1_a1 -> 0x439120，随后调用包装函数 0x439120，再进入真实处理函数 0x438e64。

第三步。0x438e64 在 0x439058 读取 wlg_guest_endis_wireless_isolation，由于该字段缺失返回 NULL；0x43907c 紧接着调用 nvram_set("endis_wlg_guest_wireless_isolation", NULL)，随后发生 SIGSEGV，si_addr=NULL。

相关问题代码：

0x438e64
