漏洞名称：
Trendnet TEW-632BRP /sbin/httpd 请求路径扩展名解析空指针解引用漏洞

Trendnet TEW-632BRP 是 Trendnet 公司旗下的一款路由器固件，受影响固件名称为 TEW-632BRP，受影响版本为 1.010b32。

tew-632brp-1.010b32
Trendnet TEW-632BRP 的 /sbin/httpd 二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过发送构造的 POST 请求，控制请求路径为不带扩展名的资源路径，使程序在解析扩展名时对空指针执行偏移和后续比较操作，最终导致 httpd 进程崩溃，造成拒绝服务风险。

该漏洞位于二进制文件 /sbin/httpd 中的请求分发主流程内。程序在 httpd_main 中接收请求路径后，会在 0x407d7c 处调用 strchr(path, '.') 查找扩展名分隔符。如果请求路径中不存在 '.'，则 strchr 返回 NULL；但程序没有检查这一返回值，而是在 0x407d88 处继续执行 NULL + 1，并在 0x407d98 处将该非法指针作为扩展名字符串参与后续比较，最终访问地址 0x00000001 并触发 SIGSEGV。

攻击者可以远程发起攻击，通过向 /vct_lan_00 这类不带扩展名的路径发送 POST 请求来触发漏洞。当前样本中的请求体仅包含 html_response_page=wzqwzqwzq，但从现有 trace 看，该字段未参与最终崩溃；真正触发问题的是请求路径 /vct_lan_00 本身。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录已经包含触发请求、执行脚本和分析记录，可直接基于现有材料复现崩溃现象。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送 POST 请求 `POST /vct_lan_00 HTTP/1.1`，请求路径 `/vct_lan_00` 进入 /sbin/httpd 的 httpd_main，并在 0x4069e4 处保存到寄存器 $18。

第二步。由于请求方法为 POST，程序会经过 do_apply_post@0x40a4bc 与 init_cgi@0x405888 处理请求体，但从当前 trace 看，请求体中的 html_response_page 参数没有继续流入最终的危险位置，流程随后仍返回到对原始请求路径的静态资源判断逻辑。

第三步。httpd_main 在 0x407d7c 处对路径 `/vct_lan_00` 调用 strchr(path, '.')。由于该路径中不包含 '.'，返回值为 NULL。程序随后在 0x407d88 处将该返回值加一得到非法地址 0x1，并在 0x407d98 处继续进行扩展名比较，最终触发 SIGSEGV。trace 和容器日志中均记录到 `si_addr=0x00000001` 与段错误现象，说明这是一个真实的空指针解引用崩溃。

![alt text](image.png)

相关问题代码：

0x407d7c
0x407d88
0x407d98
