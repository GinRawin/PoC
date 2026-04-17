漏洞名称：
Netgear XAVN2001v2 HTTP静态资源处理栈缓冲区溢出漏洞（样本id:000008）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送超长请求路径，使程序在静态资源处理函数中直接用sprintf拼接攻击者可控URI到栈缓冲区，最终覆盖返回地址并导致uhttpd进程异常退出，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理HTTP请求时，程序在handle_request函数内读取请求行并解析URI，然后根据路由表将该URI传入fcn.004059c8。该函数会把用户提供的路径分别格式化为`/tmp/%s`和`/www/%s`写入栈缓冲区`sp+0x18`。由于函数栈帧大小仅为0x140字节，保存返回地址的位置距离该缓冲区较近，而当前样本中的URI长度约1022字节，因此可以稳定覆盖返回地址。函数在返回时跳转到`0x61616160`，触发SIGSEGV。

攻击者可以远程发起攻击，通过构造包含超长路径的HTTP GET请求触发该漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中已经包含漏洞分析所需的trace、日志和样本材料，可直接用于复核崩溃路径。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送超长HTTP请求路径，uhttpd在handle_request中通过fgets读取请求行，再通过strsep拆分出URI。该URI随后被保存在`s1`中，并沿请求调度路径继续向下传递。
![alt text](image.png)

第二步。程序在0x409c80处根据handler表调用fcn.004059c8，将攻击者可控的URI作为参数传入。该函数在0x405a20和0x405a58附近使用sprintf构造`/tmp/<uri>`和`/www/<uri>`路径，目标均为位于当前栈帧中的局部缓冲区。由于没有长度限制，超长输入会覆盖保存的返回地址。
![alt text](image-1.png)

第三步。函数在0x405bac附近恢复返回现场时使用了被字符串`a`污染的返回地址，最终跳转到`0x61616160`并崩溃。trace和日志共同证明该崩溃来源于用户可控路径导致的真实栈溢出，而不是普通文件访问失败。
![alt text](image-2.png)

相关问题代码：

0x4059c8
