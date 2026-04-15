http://www.downloads.netgear.com/files/GDC/JNR3300/JNR3300-V1.0.0.34PR.zip

漏洞名称：
Netgear JNR3300 wlacl_add栈缓冲区溢出漏洞

Netgear JNR3300-1.0.0.34是Netgear旗下的一款路由器固件，受影响固件名称为JNR3300，受影响版本为1.0.0.34。

JNR3300_V1.0.0.34_10.0.17
Netgear JNR3300-1.0.0.34的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过提交超长的device和adr字段，覆盖函数返回地址并导致进程崩溃，严重情况下可能进一步实现代码执行。

该漏洞位于二进制文件usr/sbin/uhttpd中，在wlacl_add处理函数0x43b7f8内，程序先读取device与adr两个用户可控字段，随后在0x43b878处调用sprintf("%s %s")把二者拼接到sp+0x18处的栈缓冲区。由于没有长度检查，超长输入可以一直覆盖到保存的ra，trace中最终出现si_addr=0x32323232。

攻击者可以远程发起攻击，通过向/apply.cgi?c发送submit_flag=wlacl_add的POST请求，并提供超长device和adr字段来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/apply.cgi?c发送POST请求，设置submit_flag=wlacl_add，使程序进入无线ACL添加逻辑。

第二步。程序分别读取device和adr，并在0x43b878处用sprintf拼接到栈缓冲区中。由于两个字段都很长，返回地址被字符'2'覆盖，函数后续返回时导致/usr/sbin/uhttpd崩溃。
![alt text](image.png)
相关问题代码：

0x43b7f8
