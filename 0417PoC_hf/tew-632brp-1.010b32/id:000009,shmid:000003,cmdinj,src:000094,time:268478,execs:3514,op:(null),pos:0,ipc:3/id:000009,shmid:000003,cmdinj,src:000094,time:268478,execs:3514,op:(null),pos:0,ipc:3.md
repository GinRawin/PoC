https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/tew-632brp-1.010b32/tew-632brp-1.010b32.tar.gz

漏洞名称：
Trendnet TEW-632BRP 1.010B32 system 命令注入漏洞

Trendnet TEW-632BRP 1.010B32 是 Trendnet 公司旗下的一款网络设备固件，受影响产品为 TEW-632BRP，受影响版本为 1.010B32。

Trendnet TEW-632BRP 1.010B32 的 `/sbin/httpd` 二进制文件中存在一个 `命令注入` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。httpd 从 POST body 读取 wps_sta_enrollee_pin 后，直接用 snprintf("wsc_cfg pin %s", pin) 拼接 shell 命令并传给 system，未见任何 shell 元字符过滤或转义。

该漏洞位于二进制文件 `/sbin/httpd` 中。程序在 `/sbin/httpd do_apply_post@@Base+0x1f04 0x1f04` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/sbin/httpd do_apply_post@@Base+0x1f04 0x1f04` 处进入危险操作，最终导致任意命令执行风险。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/tew-632brp-1.010b32/tew-632brp-1.010b32.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。POST /set_sta_enrollee_pin.cgi* 命中 /sbin/httpd 的 handler 表，进入 0x40c39c

第二步。0x40c3f4/0x40c410 读取 wps_sta_enrollee_pin，0x40c420-0x40c47c 用 snprintf 格式化为 wsc_cfg pin <pin>

第三步。0x40c494 将该缓冲区交给 system，trace 实际观测到 /bin/sh -c "wsc_cfg pin wzqwzqwzq"

相关问题代码：

system
