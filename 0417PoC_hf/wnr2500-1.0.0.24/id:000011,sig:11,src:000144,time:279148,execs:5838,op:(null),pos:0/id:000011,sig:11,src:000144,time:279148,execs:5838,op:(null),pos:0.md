漏洞名称：
Netgear WNR2500 0x405b18 栈缓冲区溢出漏洞

Netgear WNR2500是Netgear公司旗下的一款路由器固件，受影响固件名称为WNR2500，受影响版本为1.0.0.24。

wnr2500-1.0.0.24
Netgear WNR2500的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的GET请求，使程序在处理静态页面名时将超长文件名直接格式化到固定栈缓冲区，最终覆盖返回地址并导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。程序在页面分发阶段把攻击者可控的页面名传给回调函数0x405b18。该函数会在0x405b68处执行`sprintf(sp+0x18, "/www/%s", a0)`，把页面名直接作为`%s`实参写入栈上局部缓冲区，未做长度检查。当前样本中的超长页面名导致保存的`ra`被覆盖，函数返回时跳转到`0x61616160`并触发SIGSEGV。

攻击者可以远程发起攻击，通过向设备发送带有超长静态资源名的GET请求来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。
原始固件链接为：https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/IMG_wnr2500-1.0.0.24.zip

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/wnr2500-1.0.0.24.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送GET请求，请求URI中包含超长页面名。uhttpd在静态页面处理路径中完成路由匹配后，将该页面名保存在`s1`中，并在0x408b4c处作为第一个实参传入页面处理函数0x405b18。
![alt text](image.png)

第二步。函数0x405b18在0x405b50到0x405b68之间准备`sprintf`调用，格式串为`"/www/%s"`，目的缓冲区位于`sp+0x18`。由于这里直接写入攻击者可控的超长字符串，栈帧被破坏，保存的返回地址也被覆盖。
![alt text](image-1.png)

第三步。函数继续执行到尾声0x405cf0附近时，从损坏的栈中恢复出伪造的返回地址，最终跳转到`0x61616160`并崩溃。该地址与输入中的大段`a`字符吻合，说明崩溃来自明确的可控栈溢出，而不是随机仿真异常。
![alt text](image-2.png)

相关问题代码：

0x405b18
