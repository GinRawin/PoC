https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/xavn2001v2-0.4.0.7/xavn2001v2-0.4.0.7.tar.gz

漏洞名称：
Netgear XAVN2001v2 0.4.0.7 0x4391c0 空指针解引用漏洞

Netgear XAVN2001v2 0.4.0.7 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XAVN2001v2，受影响版本为 0.4.0.7。

Netgear XAVN2001v2 0.4.0.7 的 `/usr/sbin/uhttpd` 二进制文件中存在一个 `空指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。submit_flag=wlan 将请求路由到无线配置处理路径后，代码对 cgi_value("wl_enable_ssid_broadcast", ...) 的返回值不判空，直接作为 nvram_set("wla_endis_ssid_broadcast", value) 的第二个实参使用，缺失该字段时触发空指针崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。程序在 `/usr/sbin/uhttpd sym.cgi_value 0x40b4a4` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/usr/sbin/uhttpd fcn.00439154 0x4391c0` 处进入危险操作，最终导致进程崩溃并造成拒绝服务。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/xavn2001v2-0.4.0.7/xavn2001v2-0.4.0.7.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。uhttpd 处理本次 POST /apply.cgi?... 请求，body.submit_flag = "wlan" 命中无线设置分支，而不是 VulPacket.json 中的 handler_name 字面值。

第二步。0x439134 调用 fcn.00438e64，随后进入 0x439154 对无线相关 CGI 参数逐个取值并写 NVRAM。

第三步。0x4391a0 调用 cgi_value("wl_enable_ssid_broadcast", ...) 得到 NULL，0x4391c0 将其传给 nvram_set，最终在该基本块内触发 SIGSEGV。

相关问题代码：

0x4391c0
