http://www.downloads.netgear.com/files/GDC/JNR3300/JNR3300-V1.0.0.34PR.zip

漏洞名称：
Netgear JNR3300 1.0.0.34 uhttpd 静态文件路径拼接栈缓冲区溢出漏洞

Netgear JNR3300-1.0.0.34是Netgear旗下的一款路由器固件，受影响固件名称为JNR3300，受影响版本为1.0.0.34。

JNR3300_V1.0.0.34_10.0.17
Netgear JNR3300-1.0.0.34的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的超长GET请求URI触发静态资源处理流程，在路径拼接阶段覆盖栈上的保存寄存器，从而导致httpd进程崩溃并造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。程序在handle_request函数中解析HTTP请求行，提取攻击者可控的URI字段后，将其传入静态文件处理函数fcn.004060f8。该函数在0x00406130处调用sprintf，将外部可控的URI按"/www/%s"格式写入栈上固定缓冲区sp+0x18，但没有进行长度校验。当请求URI过长时，会覆盖当前栈帧中的s0、s1、s2和ra等保存寄存器，并在函数尾声0x004061fc附近恢复寄存器时触发SIGSEGV。

攻击者可以远程发起攻击，通过向设备发送超长的GET请求，例如访问以/cc.gif开头并携带大段填充数据的恶意路径，使请求命中.gif相关静态文件分支，最终进入上述危险的sprintf路径并触发崩溃。

漏洞研究环境：

通过模拟仿真进行验证。当前分析基于greenhouse仿真环境中的运行结果，目标程序为/usr/sbin/uhttpd。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向目标服务发送恶意GET请求，请求行为以/cc.gif开头，并在URI中拼接大量攻击者可控字符。当前样本的原始请求中，请求路径后还带有?block_skeyword=wzqwzqwzq查询字符串，用于保持请求格式完整。

第二步。/usr/sbin/uhttpd在handle_request中读取并解析请求行，使用strsep拆分方法、URI和协议版本。解析得到的URI token被保存到局部变量s1，并经过.gif相关分支判断后，进入静态文件处理回调。

第三步。静态文件处理函数fcn.004060f8使用sprintf(sp+0x18, "/www/%s", uri)拼接目标文件路径。由于目标缓冲区位于栈上且大小固定，而传入的uri完全由请求控制，因此超长输入会直接破坏当前栈帧。

第四步。函数继续执行并准备返回时，在0x004061fc附近恢复被破坏的保存寄存器，最终触发SIGSEGV。trace中可以观察到程序路径经过0x004060f8、0x00406130并在0x004061fc崩溃，崩溃地址表现出明显的输入污染特征，说明这是由可控栈溢出引起的拒绝服务。
![alt text](image.png)

相关问题代码：

0x004060f8
