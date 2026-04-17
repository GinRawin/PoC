https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x40c8b0 栈缓冲区溢出漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 /sbin/httpd 二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过向 /ntp_sync.cgi* 发送构造的 POST 请求，控制 ntp_server 参数内容，使其在 sprintf 格式化过程中覆盖栈上的保存寄存器和返回地址，最终造成 httpd 进程崩溃，具备进一步控制程序执行流的风险。

该漏洞位于二进制文件 /sbin/httpd 的 NTP 同步处理函数中。程序在 0x40c994 处通过 get_cgi("ntp_server") 读取 POST 参数，在 0x40c9c4 处使用 sprintf 将用户输入拼接进 ntpclient -h %s -s -i 5 -c 1 命令字符串，目标缓冲区位于栈上的 sp+0x18 附近，但该缓冲区长度明显不足以容纳当前样本中的超长 ntp_server 内容。随后程序虽然仍在 0x40c9f8 处调用 _system 执行命令，但当函数走到 0x40ca64 附近的尾声时，保存的返回地址已经被覆盖，最终跳转到 0x61615f60 并触发 SIGSEGV。当前样本的请求包为 POST /ntp_sync.cgi* HTTP/1.1，请求体中携带超长 ntp_server、html_response_page 和 er_ip_08_B，其中导致栈溢出的核心字段是 ntp_server。

攻击者可以远程发起攻击，通过向 /ntp_sync.cgi* 发送超长 ntp_server 参数触发漏洞。根据现有 trace、容器日志和反汇编证据，程序先生成包含攻击者数据的 ntpclient 命令并执行，随后在返回路径上因返回地址被污染而崩溃。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 /ntp_sync.cgi* 发送 POST 请求，请求体中携带超长 ntp_server 参数，使程序进入 NTP 同步处理分支。

第二步。程序在 0x40c994 处读取 ntp_server 参数内容，并在 0x40c9c4 处通过 sprintf 将其写入位于栈上的命令缓冲区。由于该缓冲区空间有限，而输入长度远超其可承载范围，栈上的保存寄存器和返回地址被覆盖。

第三步。程序在 0x40c9f8 处调用 _system 执行拼接后的命令，待函数执行到 0x40ca64 附近准备返回时，返回地址已经被用户输入污染，最终跳转到异常地址并触发 SIGSEGV。
![alt text](image.png)

相关问题代码：

0x40c8b0
