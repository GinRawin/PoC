https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x40c9c4 栈缓冲区溢出(返回地址覆写)漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 `/sbin/httpd` 二进制文件中存在一个 `栈缓冲区溢出(返回地址覆写)` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。httpd 在 ntp_sync.cgi 处理函数中把 body.ntp_server 直接传给 sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ...)，目标栈缓冲区只有 32 字节，导致保存的 ra 被覆盖并在函数返回时跳到攻击者可控地址。

该漏洞位于二进制文件 `/sbin/httpd` 中。程序在 `/sbin/httpd fcn.0040c8b0 0x40c994` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/sbin/httpd fcn.0040c8b0 0x40c9c4` 处进入危险操作，最终导致栈破坏并触发进程崩溃。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。POST /ntp_sync.cgi 进入 httpd 的 fcn.0040c8b0，随后读取 body.ntp_server

第二步。该值被 sprintf 拼进栈上的命令字符串 ntpclient -h %s -s -i 5 -c 1，溢出覆盖保存的寄存器和 ra

第三步。_system 执行命令返回后，函数尾声执行到 0x40ca64 附近，最终按被污染的 ra 跳转到 0x61615f60 并触发 SIGSEGV

相关问题代码：

0x40c9c4
