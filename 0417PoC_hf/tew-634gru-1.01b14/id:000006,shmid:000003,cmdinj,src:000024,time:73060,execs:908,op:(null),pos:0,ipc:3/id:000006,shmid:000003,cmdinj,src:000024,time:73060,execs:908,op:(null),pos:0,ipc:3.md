https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x40c8b0 命令注入漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /ntp_sync.cgi* 发送构造的 POST 请求，控制 ntp_server 参数内容，使其进入 shell 命令拼接流程并被 /bin/sh -c 执行，从而造成任意命令执行。

该漏洞位于二进制文件 /sbin/httpd 中的 do_ntp_sync 处理逻辑内。程序在 0x40c978 处通过 get_cgi("ntp_server") 读取 POST 参数，在 0x40c9a0 至 0x40c9c4 处使用 sprintf 将用户输入拼接进 ntpclient -h %s -s -i 5 -c 1 命令模板，随后在 0x40ca08 处调用 _system 执行该命令。由于整个过程中没有对用户输入进行 shell 元字符过滤，因此攻击者可以通过构造 ntp_server 参数实现命令注入。当前样本的请求包为 POST /ntp_sync.cgi* HTTP/1.1，请求体中携带 ntp_server=wzqwzqwzq、er_ip_08_B=wzqwzqwzq 和 html_response_page=wzqwzqwzq，其中真正流入危险命令拼接点的是 ntp_server 字段。

攻击者可以远程发起攻击，通过向 /ntp_sync.cgi* 发送包含恶意 ntp_server 参数的 POST 请求触发漏洞。根据现有 trace，_system 最终经由 /bin/sh -c 执行了 ntpclient -h wzqwzqwzq -s -i 5 -c 1，说明该参数已经真实进入 shell 执行路径。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /ntp_sync.cgi* 发送 POST 请求，请求体中携带 ntp_server 参数，使程序进入 NTP 同步处理分支。

第二步。程序在 0x40c978 处读取 ntp_server 参数内容，并在 0x40c9a0 至 0x40c9c4 处将其拼接到 ntpclient -h %s -s -i 5 -c 1 命令模板中。

第三步。程序在 0x40ca08 处调用 _system 执行拼接后的命令。trace 进一步显示该命令经 /bin/sh -c 解释执行，因此只要 ntp_server 中包含恶意 shell 元字符，即可实现任意命令执行。
![alt text](image.png)

相关问题代码：

0x40c8b0

