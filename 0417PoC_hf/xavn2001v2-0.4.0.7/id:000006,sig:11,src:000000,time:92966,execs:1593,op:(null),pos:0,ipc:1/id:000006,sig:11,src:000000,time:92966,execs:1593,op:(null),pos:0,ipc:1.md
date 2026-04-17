漏洞名称：
Netgear XAVN2001v2 HTTP请求路径处理栈缓冲区溢出漏洞（样本id:000006）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送包含超长URI的HTTP请求，使程序在静态页面路由处理过程中将攻击者可控路径直接格式化到栈缓冲区中，最终覆写返回地址并导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理HTTP请求时，程序会在handle_request函数中解析请求行，提取用户可控的URI，并根据路由表匹配`.htm`后缀对应的处理函数。当前样本中，handle_request将超长URI传入0x40fa88对应的处理函数，后者在0x40fae0和0x40fb34两处调用sprintf，将URI分别拼接为`/tmp/%s`和`/www/%s`写入栈上缓冲区`sp+0x18`。由于该写入没有长度检查，超长输入会覆盖保存的返回地址，函数返回时跳转到被污染的地址`0x61616160`并触发崩溃。

攻击者可以远程发起攻击，通过发送命中`.htm`静态资源处理路径的超长GET请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中保留了该漏洞的分析材料、trace和运行日志，可用于复现崩溃路径。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送包含超长URI的HTTP请求，uhttpd在handle_request中使用fgets和strsep解析请求行，并将请求路径保存到局部变量中。随后程序遍历静态资源路由表，发现该路径包含`.htm`子串，因此命中对应的处理函数0x40fa88。
![alt text](image.png)

第二步。handle_request在0x409c80处将攻击者可控的URI作为参数传入0x40fa88。该函数分别在0x40fae0和0x40fb34两处执行sprintf，将超长路径写入位于栈上的目标缓冲区。由于缓冲区与保存返回地址之间距离有限，而当前URI长度远超可用空间，最终覆盖返回地址。
![alt text](image-1.png)

第三步。函数在0x40fd14附近进入尾声并恢复寄存器时，使用了已经被污染的返回地址，最终跳转到`0x61616160`并触发SIGSEGV。trace和容器日志均显示崩溃发生在该返回阶段，说明这是一个可由远程请求直接触发的真实栈溢出漏洞。
![alt text](image-2.png)

相关问题代码：

0x40fa88
