漏洞名称：
Trendnet TEW-632BRP 0x40ea3c 命令注入漏洞

Trendnet TEW-632BRP 是 Trendnet 公司旗下的一款路由器固件，受影响固件名称为 TEW-632BRP，受影响版本为 1.010b32。

tew-632brp-1.010b32
Trendnet TEW-632BRP 的 /sbin/httpd 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 /system_time.cgi* 发送构造的 POST 请求，控制时间设置相关参数内容，使用户输入在系统时间设置流程中被直接拼接进 shell 命令并执行，从而造成任意命令执行风险。

该漏洞位于二进制文件 /sbin/httpd 中，在 system_time.cgi* 对应的处理分支内，程序会在 0x40ea80 处调用 get_cgi("version_date") 读取用户可控数据，并在 0x40eac4 附近装载格式串 `date -s %s `，随后在 0x40eadc 处调用 _system 执行该命令。由于用户输入在进入 shell 前没有经过过滤、转义或引号包裹，攻击者可以构造恶意参数触发命令注入。

攻击者可以远程发起攻击，通过向 /system_time.cgi* 发送 POST 请求，并在 date 参数中插入恶意命令内容来触发漏洞。当前样本中使用的是一个超长字符串，因此容器日志表现为 `/bin/date` 报错 `invalid date`；但从已有数据流和 sink 行为看，只要在同一位置放入 shell 元字符，即可将该路径从参数污染升级为命令执行。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录已经包含触发请求、执行脚本和现有分析材料，可直接复现该命令构造与调用行为。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送 `POST /system_time.cgi* HTTP/1.1` 请求，请求体中包含 date 参数。现有请求样本为 `date=aaaaaaaa...` 这一长字符串，请求到达后命中 system_time.cgi* 对应的处理函数入口 0x40ea3c。

第二步。该处理分支在 0x40ea74-0x40ea88 处调用 get_cgi，并以 `version_date` 作为键名读取 CGI 参数，将返回值保存到寄存器 s0。虽然原始请求中字段名表现为 date，但从现有反汇编和行为证据看，该输入最终以 `version_date` 的形式被内部逻辑取出。

第三步。程序在 0x40eabc 处将用户可控值作为 _system 的第二个参数，在 0x40eac4 处装载格式串 `date -s %s `，并在 0x40eadc 处调用 _system 执行格式化后的 shell 命令。容器日志显示后续确实拉起了 `/bin/sh` 和 `/bin/date`，且 `/bin/date` 收到的参数与样本中的超长字符串一致，证明用户输入已经直接进入 shell 命令执行链路。

第四步。当前样本因为输入内容不是合法日期，最终表现为 `date: invalid date`。但这并不影响漏洞成立，因为危险点在于 `/sbin/httpd` 已经把外部可控数据直接拼接进 `date -s %s ` 并交给 shell 解释执行；在同一路径下改用分号、反引号或 `$()` 等特殊字符即可实现命令注入。

![alt text](image.png)

相关问题代码：

0x40ea3c
0x40ea80
0x40eadc
