漏洞名称：
Netgear WNR2500 0x405d20 栈缓冲区溢出漏洞

Netgear WNR2500是Netgear公司旗下的一款路由器固件，受影响固件名称为WNR2500，受影响版本为1.0.0.24。

wnr2500-1.0.0.24
Netgear WNR2500的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的GET请求，使程序在处理`.gif`样式静态资源时，将超长URI直接拼接到固定大小的栈缓冲区中，最终覆盖保存寄存器并导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。程序在handle_request中解析请求行后，会将请求URI交给静态路由分发表匹配。当前样本中的超长URI包含`.gif`子串，因此命中处理函数0x405d20。该函数在0x405d58处调用`sprintf("/www/%s", uri)`，把攻击者可控的完整URI写入栈上`sp+0x18`附近的固定缓冲区，没有进行边界检查。超长输入覆盖了保存的`s1`等栈内容，后续在0x405d90处继续把已被污染的`s1`当作合法指针使用，最终触发SIGSEGV。

攻击者可以远程发起攻击，通过向设备发送包含超长`.gif`路径的GET请求来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。
原始固件链接为：https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/IMG_wnr2500-1.0.0.24.zip

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/wnr2500-1.0.0.24.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送超长GET请求，请求路径形如`/upgrade.cgicc.gif...`。handle_request对请求行执行strsep拆分后，取出第二个token作为URI，并在路由循环中使用`strstr(uri, ".gif")`匹配静态资源处理表项，因此控制流进入`.gif`对应的处理函数0x405d20。
![alt text](image.png)

第二步。在0x405d20中，程序直接调用`sprintf("/www/%s", uri)`把超长URI写入栈缓冲区。由于目标缓冲区长度固定且没有边界检查，长字符串覆盖了当前栈帧中的保存寄存器，尤其是后续要使用的`s1`。
![alt text](image-1.png)

第三步。函数继续向后执行，在0x405d90处又从被覆盖后的`s1`取偏移值并进行解引用，崩溃地址表现为`0x77616160`，与攻击字符串覆盖后的内存模式一致，因此可以确认这里不是误报，而是由前面的栈溢出直接导致的崩溃。
![alt text](image-2.png)

相关问题代码：

0x405d20
