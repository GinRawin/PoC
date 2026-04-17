https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x424184 命令注入漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /set_sta_enrollee_pin.cgi* 发送构造的 POST 请求，控制 wps_sta_enrollee_pin 参数内容，使其进入 shell 命令拼接流程并被 /bin/sh -c 执行，从而造成任意命令执行。

该漏洞位于二进制文件 /sbin/httpd 中的 set_sta_enrollee_pin 函数内。程序在 0x4241a0 处接收由请求体传入的 wps_sta_enrollee_pin 参数，在 0x424204 处将该值格式化进 wsc_cfg pin %s 命令字符串，随后在 0x424230 处调用 _system 执行。由于整个过程中没有对 shell 元字符进行转义或过滤，攻击者可以利用该参数执行任意命令。当前样本的请求包为 POST /set_sta_enrollee_pin.cgi* HTTP/1.1，请求体中不仅包含超长的 wps_sta_enrollee_pin，还额外携带 er_ip_08_B=;`wzq` 与异常的 html_response_page 字段；但根据现有 trace 与反汇编证据，真正流入 _system 命令字符串的是 wps_sta_enrollee_pin，该请求随后被执行为 /bin/sh -c "wsc_cfg pin <payload>"。本次样本在命令执行后还伴随出现 SIGSEGV，但这属于危险执行路径后的次级异常，不影响命令注入结论。

攻击者可以远程发起攻击，通过向 /set_sta_enrollee_pin.cgi* 发送包含恶意 wps_sta_enrollee_pin 参数的 POST 请求触发漏洞。由于 sink 是标准的 _system 调用，只要参数中包含 shell 特殊字符，就会在 shell 解释阶段被执行。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /set_sta_enrollee_pin.cgi* 发送 POST 请求，请求体中携带 wps_sta_enrollee_pin 参数，使程序进入对应的 WPS PIN 处理逻辑。

第二步。程序在 set_sta_enrollee_pin 中接收该参数，并在 0x424204 处将其拼接为 wsc_cfg pin %s 命令字符串。

第三步。程序在 0x424230 处调用 _system 执行拼接后的命令。trace 记录显示该调用实际经由 /bin/sh -c 执行，证明攻击者可控数据已经进入 shell 解释流程，因此形成命令注入。
![alt text](image.png)

相关问题代码：

0x424184

