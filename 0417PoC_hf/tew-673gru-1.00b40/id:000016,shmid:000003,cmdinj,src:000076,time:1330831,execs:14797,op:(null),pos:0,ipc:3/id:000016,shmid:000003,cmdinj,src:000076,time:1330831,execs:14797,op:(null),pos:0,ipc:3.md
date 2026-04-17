https://www.trendnet.com/support/support-detail.asp?prod=160_TEW-673GRU

漏洞名称：
Trendnet TEW-673GRU 1.00B40 /sbin/httpd ntp_sync.cgi 命令注入漏洞

Trendnet TEW-673GRU 1.00B40 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-673GRU，受影响版本为 1.00B40。

Trendnet TEW-673GRU 1.00B40 的 `/sbin/httpd` 二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向 `/ntp_sync.cgi*` 发送构造的 POST 请求，控制 `ntp_server` 参数内容。程序会将该参数直接拼接进 `ntpclient -h %s -s -i 5 -c 1` 命令字符串，并通过 `_system()` 交给 `/bin/sh -c` 执行。由于这里没有进行转义或过滤，攻击者可借此注入额外 shell 命令，最终导致任意命令执行。

该漏洞位于二进制文件 `/sbin/httpd` 中的 NTP 同步处理函数 `fcn.0040d930`。程序在 `0x40da14` 处通过 `get_cgi("ntp_server")` 读取用户可控参数，在 `0x40da44` 处调用 `sprintf` 将输入拼接到命令模板中，并在 `0x40da78` 处调用 `_system()` 执行。现有 trace 已显示命令链路从 `httpd` 进入 `/bin/sh -c "ntpclient -h wzqwzqwzq -s -i 5 -c 1"`，说明外部输入确实到达了 shell 解释环境。

攻击者可以远程发起攻击，通过向 `/ntp_sync.cgi*` 发送包含恶意 `ntp_server` 参数的 POST 请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求样本与分析结果，原始固件可通过上述下载链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。相关样本基于当前目录中的运行与 trace 结果完成分析。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 `/ntp_sync.cgi*` 发送 POST 请求，请求体中包含 `p_default_key=\`wzq\`&ntp_server=wzqwzqwzq`，其中 `ntp_server` 为用户可控字段。

第二步。程序在 `0x40da14` 处调用 `get_cgi("ntp_server")` 读取参数内容，并在 `0x40da44` 处通过 `sprintf` 生成 `ntpclient -h %s -s -i 5 -c 1` 命令字符串，将结果写入栈缓冲区。

第三步。程序在 `0x40da78` 处调用 `_system()` 执行该命令。trace 与控制台日志显示实际执行链为 `/bin/sh -c "ntpclient -h wzqwzqwzq -s -i 5 -c 1"`，证明用户输入已经在未经过滤的情况下进入 shell 执行路径，因此构成命令注入漏洞。

![alt text](image.png)

相关问题代码：

0x40d930
