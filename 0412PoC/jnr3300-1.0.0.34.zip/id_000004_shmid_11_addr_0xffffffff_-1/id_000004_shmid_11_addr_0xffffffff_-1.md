http://www.downloads.netgear.com/files/GDC/JNR3300/JNR3300-V1.0.0.34PR.zip

漏洞名称：
Netgear JNR3300 0x437978 空指针解引用漏洞

Netgear JNR3300-1.0.0.34是Netgear旗下的一款路由器固件，受影响固件名称为JNR3300，受影响版本为1.0.0.34。

JNR3300_V1.0.0.34_10.0.17
Netgear JNR3300-1.0.0.34的/usr/sbin/uhttpd二进制文件中存在一个空指针解引用漏洞。远程攻击者在L2TP配置页面提交构造请求后，可以利用缺失的DNS参数触发strcpy对NULL源指针的访问，导致设备拒绝服务。

该漏洞位于二进制文件usr/sbin/uhttpd中，在L2TP处理函数0x437978内，程序在DNSAssign分支下依次读取l2tp_dnsaddr1和l2tp_dnsaddr2。当l2tp_dnsaddr2缺失时，cgi_value在0x437a70处返回NULL，随后代码在0x437a84处执行strcpy(dst, NULL)，最终触发崩溃。

攻击者可以远程发起攻击，通过向/apply.cgi?c发送submit_flag=l2tp的POST请求，并在DNSAssign有效的情况下省略l2tp_dnsaddr2字段来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/jnr3300-1.0.0.34.zip/jnr3300-1.0.0.34.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/apply.cgi?c发送POST请求，设置submit_flag=l2tp，并提供DNSAssign和l2tp_dnsaddr1，使程序进入L2TP手工DNS配置分支。

第二步。程序继续读取l2tp_dnsaddr2，但样本中该字段缺失，cgi_value返回NULL。函数随后在0x437a84处执行strcpy，将NULL作为源指针复制到栈缓冲区，最终导致/usr/sbin/uhttpd崩溃。
![alt text](image.png)
相关问题代码：

0x437978
