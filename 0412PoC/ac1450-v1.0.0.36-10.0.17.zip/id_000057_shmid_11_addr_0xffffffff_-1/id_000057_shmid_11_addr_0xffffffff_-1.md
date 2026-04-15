http://www.downloads.netgear.com/files/GDC/AC1450/AC1450-V1.0.0.36_10.0.17.zip
Netgear AC1450-1.0.0.36是Netgear旗下的一款路由器固件，受影响固件名称为AC1450，受影响版本为1.0.0.36。

AC1450_V1.0.0.36_10.0.17
漏洞名称：Netgear AC1450 静态路由处理函数 缓冲区溢出漏洞
Netgear AC1450-1.0.0.36 httpd 二进制文件包含一个栈缓冲区溢出漏洞，会导致经过身份验证的远程攻击者能够覆盖返回地址，从而使目标设备dos或执行远程代码。

该漏洞位于二进制文件 usr/sbin/httpd 中，在静态路由处理函数地址 0x2d0dc 处将route_name逐字节写入固定长度栈缓冲区时没有进行边界检查。

攻击者可以远程发起攻击，通过发送构造的恶意数据包触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/Netgear/ac1450/ac1450rehost.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

我还附上了复现请求文件，直接重放当前目录下的packet_1.request.raw即可。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送一个恶意数据包，路由信息为/routinfo.cgi?st_dhcp.cgi，数据包中的route_name参数长度为128字节。处理函数先在地址0x2d040附近调用sub_1654c，把route_name取出并写入sp+0x3000。

第二步。随后静态路由处理函数会在地址0x2d05c到0x2d0dc之间把route_name重新逐字节转写到sp+0x6c78开始的64字节栈缓冲区，但循环只参考route_name自身长度，没有检查目标缓冲区大小。

第三步。由于sp+0x6c78到保存的返回地址只有0x5c字节，128字节的2222字符串会覆盖返回地址。函数在地址0x2d4c8返回时，程序跳到0x32323232并触发SIGSEGV崩溃。

相关问题代码：

静态路由处理函数
