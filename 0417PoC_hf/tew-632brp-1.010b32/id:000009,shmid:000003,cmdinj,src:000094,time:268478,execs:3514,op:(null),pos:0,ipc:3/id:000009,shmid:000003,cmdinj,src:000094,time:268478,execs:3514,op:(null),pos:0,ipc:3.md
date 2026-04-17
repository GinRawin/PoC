漏洞名称：
Trendnet TEW-632BRP set_sta_enrollee_pin.cgi* 命令注入漏洞

Trendnet TEW-632BRP 是 Trendnet 公司旗下的一款路由器固件，受影响固件名称为 TEW-632BRP，受影响版本为 1.010b32。

tew-632brp-1.010b32
Trendnet TEW-632BRP 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /set_sta_enrollee_pin.cgi* 发送构造的 POST 请求，控制 wps_sta_enrollee_pin 参数内容，使该值在 WPS 配置流程中被直接拼接进 shell 命令并执行，从而造成任意命令执行风险。

该漏洞位于二进制文件 /sbin/httpd 中 set_sta_enrollee_pin.cgi* 对应的处理分支内。程序在 0x40c3f4/0x40c410 附近读取参数 `wps_sta_enrollee_pin`，随后在 0x40c420-0x40c47c 处使用 `snprintf("wsc_cfg pin %s", pin)` 构造命令字符串，并在 0x40c494 处调用 system 执行。由于用户输入在进入 shell 前没有经过过滤、转义或白名单校验，攻击者可以通过该参数实现命令注入。

攻击者可以远程发起攻击，通过向 /set_sta_enrollee_pin.cgi* 发送 POST 请求，并在 wps_sta_enrollee_pin 参数中插入恶意命令内容来触发漏洞。当前样本中的参数值为 `wzqwzqwzq`，因此执行结果只表现为 `/sbin/wsc_cfg` 对 PIN 长度报错；但从现有 trace 可以确认，该值已经原样进入 `/bin/sh -c` 的命令字符串中。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录已经包含触发请求、执行脚本和分析结果，可直接基于现有材料复现该命令执行路径。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送 `POST /set_sta_enrollee_pin.cgi* HTTP/1.1` 请求，请求体中包含 `wps_sta_enrollee_pin=wzqwzqwzq` 与 `html_response_page=...`。其中真正影响漏洞触发的是 `wps_sta_enrollee_pin`，而 `html_response_page` 仅用于后续页面跳转或回显。

第二步。请求命中 /sbin/httpd 中对应的 CGI handler，并进入 0x40c39c 开始的处理分支。程序在 0x40c3f4/0x40c410 附近取出 `wps_sta_enrollee_pin` 的值，随后将该值继续向下传递给命令格式化逻辑。

第三步。程序在 0x40c420-0x40c47c 处调用 snprintf，将用户输入按 `wsc_cfg pin %s` 的格式写入栈上命令缓冲区；之后又会通过调试输出打印 `set_sta_enrollee_pin=%s`，说明该缓冲区中保存的确实是最终待执行命令。

第四步。程序在 0x40c494 处将该缓冲区交给 system，trace 中可以直接看到后续执行链为 `/bin/sh -c "wsc_cfg pin wzqwzqwzq"`。容器日志还显示 `/sbin/wsc_cfg` 被启动，并输出 `Invalid pin entered, pin length must be 8!`。这说明输入校验发生在 shell 命令已经构造并执行之后，因此该路径属于真实的命令注入风险，而不是单纯的业务调用。

![alt text](image.png)

相关问题代码：

0x40c39c
0x40c420
0x40c494
