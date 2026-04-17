https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x40ebd4 命令注入漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /system_time.cgi* 发送构造的 POST 请求，控制 date 参数内容，使其进入 shell 命令拼接流程并被 /bin/sh -c 执行，从而造成任意命令执行。

该漏洞位于二进制文件 /sbin/httpd 中的 system_time 相关处理逻辑内。程序在 0x40ec18 处通过 get_cgi("date") 读取 POST 参数，在 0x40ec50 至 0x40ec74 处将用户输入带入 _system("date -s %s", <user_input>) 调用。由于整个过程中没有对输入内容进行过滤或限制，攻击者可以通过构造 date 参数实现命令注入。当前样本的请求包为 POST /system_time.cgi* HTTP/1.1，请求体中携带 html_response_return_page='wzq'、date=wzqwzqwzq 和 er_ip_08_B=wzqwzqwzq，其中真正流入危险执行点的是 date 字段。

攻击者可以远程发起攻击，通过向 /system_time.cgi* 发送包含恶意 date 参数的 POST 请求触发漏洞。根据现有 trace，程序最终经由 /bin/sh -c 执行了 date -s wzqwzqwzq，说明 date 字段已经真实进入 shell 执行路径。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /system_time.cgi* 发送 POST 请求，请求体中携带 date 参数，使程序进入系统时间设置处理逻辑。

第二步。程序在 0x40ec18 处读取 date 参数内容，并在 0x40ec50 至 0x40ec74 处将其作为 date -s %s 命令模板的可控部分传入 _system。

第三步。程序调用 _system 后，命令经 /bin/sh -c 解释执行。由于 date 参数缺乏 shell 级过滤，只要插入合适的 shell 特殊字符，即可实现任意命令执行。
![alt text](image.png)

相关问题代码：

0x40ebd4

