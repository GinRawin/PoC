漏洞名称：
Netgear XAVN2001v2 GIF资源处理栈缓冲区溢出漏洞（样本id:000019）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送包含超长`.gif`资源名的HTTP请求，使程序在静态文件处理函数中将攻击者可控路径直接写入栈缓冲区，导致返回现场被破坏并触发uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理HTTP请求时，handle_request会根据请求路径后缀匹配静态资源分发表。当前样本中的超长请求路径以`.gif`结尾，因此命中`.gif`对应的处理函数sym.make_funcsjs。程序在0x409c80处将请求路径作为参数传入该函数，而该函数会在0x405c24和0x405c5c两处调用sprintf，把路径分别格式化为`/tmp/%s`和`/www/%s`写入栈缓冲区`sp+0x18`。由于目标缓冲区位于0xb0字节大小的栈帧内，超长输入会覆盖保存寄存器和返回地址，最终在0x405cf8附近恢复栈帧时触发崩溃。

攻击者可以远程发起攻击，通过发送包含超长`.gif`路径的HTTP GET请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中保存了trace、日志和分析材料，能够复核请求路径进入`.gif`处理函数并最终覆盖返回现场的过程。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送包含超长`.gif`资源名的HTTP请求，uhttpd在handle_request中解析出请求路径，并在静态资源路由表中匹配到`.gif`对应的处理项。
![alt text](image.png)

第二步。handle_request在0x409c80处调用sym.make_funcsjs，将用户可控路径作为参数传入。该函数在0x405c24和0x405c5c两处使用sprintf构造本地文件路径，写入位于栈上的目标缓冲区。由于没有长度检查，超长`.gif`文件名会越界覆盖返回现场。
![alt text](image-1.png)

第三步。程序在0x405cf8附近恢复寄存器时使用了已经被污染的栈内容，最终触发SIGSEGV。trace中的`si_addr=0x6966008c`保留了`.gif`字符串痕迹，说明崩溃与请求路径污染返回现场直接相关。
![alt text](image-2.png)

相关问题代码：

0x405bdc
