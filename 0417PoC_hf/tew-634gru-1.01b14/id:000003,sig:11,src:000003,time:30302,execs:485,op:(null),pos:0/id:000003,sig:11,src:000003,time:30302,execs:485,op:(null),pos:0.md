https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 /sbin/httpd 路径扩展名处理空指针解引用漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向 /vct_lan_00 发送构造的 POST 请求，使程序在处理请求路径扩展名时对空指针执行偏移和后续字符串比较，最终造成 httpd 进程崩溃，形成拒绝服务。

该漏洞位于二进制文件 /sbin/httpd 中的 httpd_main 路径处理逻辑内。程序在 0x407ab8 处将请求目标去掉前导斜杠后得到字符串 vct_lan_00，并在 0x407e7c 处调用 strchr(path, '.') 试图查找扩展名分隔符。由于该请求路径不包含点号，strchr 返回 NULL，但代码在 0x407e88 处仍继续执行 v0 + 1，并在 0x407e98 处把地址 0x00000001 作为字符串指针传入后续比较函数，最终触发 SIGSEGV。当前样本的请求包为 POST /vct_lan_00 HTTP/1.1，请求体中仅携带 html_response_page=wzqwzqwzq，说明崩溃根因来自请求路径本身，而不是某个表单字段被复杂解析后的结果。

攻击者可以远程发起攻击，通过发送不带扩展名的 CGI 风格 POST 请求触发漏洞。根据现有 trace 与反汇编证据，请求首先命中 do_apply_post 路径，随后返回 httpd_main 继续做扩展名判断，并在 0x407e84 之后访问非法地址 0x1。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /vct_lan_00 发送 POST 请求，请求目标中不包含 . 字符，程序在 httpd_main 中将该路径去掉前导 / 后得到 vct_lan_00。

第二步。程序在 0x407e7c 处调用 strchr 查找扩展名分隔符。由于路径中不存在点号，该调用返回 NULL。

第三步。程序在 0x407e88 处没有检查返回值，直接将 NULL 加一得到 0x00000001，并在 0x407e98 处把该非法地址继续传给后续字符串比较逻辑，最终触发 SIGSEGV，导致 httpd 进程崩溃。
![alt text](image.png)

相关问题代码：

0x407e7c

