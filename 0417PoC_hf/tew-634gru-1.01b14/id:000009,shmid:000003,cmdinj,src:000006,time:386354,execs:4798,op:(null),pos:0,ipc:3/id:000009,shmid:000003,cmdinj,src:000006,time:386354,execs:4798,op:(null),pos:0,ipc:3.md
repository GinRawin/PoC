https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x40c534 命令注入漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /set_sta_enrollee_pin.cgi* 发送构造的 POST 请求，控制 wps_sta_enrollee_pin 参数内容，使其进入 shell 命令拼接流程并被 system 调用执行，从而造成任意命令执行。

该漏洞位于二进制文件 /sbin/httpd 中 do_apply_post 的相关处理分支内。程序在 0x40c5a8 处通过 get_cgi("wps_sta_enrollee_pin") 读取 POST 参数，在 0x40c608 处将该值写入 enrollee 相关对象，并在 0x40c610 处使用 sprintf 将其拼接进 wsc_cfg pin %s 命令模板，随后在 0x40c644 处调用 system 执行。由于整个过程中没有对用户输入进行 shell 级过滤，因此攻击者可以通过构造 wps_sta_enrollee_pin 参数实现命令注入。当前样本的请求包为 POST /set_sta_enrollee_pin.cgi* HTTP/1.1，请求体中携带 wps_sta_enrollee_pin=wzqwzqwzq、er_ip_08_B=wzqwzqwzq 和 html_response_page=wzqwzqwzq，其中真正流入危险命令拼接点的是 wps_sta_enrollee_pin 字段。

攻击者可以远程发起攻击，通过向 /set_sta_enrollee_pin.cgi* 发送包含恶意 wps_sta_enrollee_pin 参数的 POST 请求触发漏洞。根据现有 trace，system 最终经由 /bin/sh -c 执行了 wsc_cfg pin wzqwzqwzq，说明该参数已经真实进入 shell 执行路径。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /set_sta_enrollee_pin.cgi* 发送 POST 请求，请求体中携带 wps_sta_enrollee_pin 参数，使程序进入 do_apply_post 的对应处理分支。

第二步。程序在 0x40c5a8 处读取 wps_sta_enrollee_pin 参数内容，并在 0x40c610 处将其拼接到 wsc_cfg pin %s 命令模板中。

第三步。程序在 0x40c644 处调用 system 执行拼接后的命令。trace 进一步显示该命令经 /bin/sh -c 解释执行，因此只要 wps_sta_enrollee_pin 中包含恶意 shell 元字符，即可实现任意命令执行。
![alt text](image.png)

相关问题代码：

0x40c534

