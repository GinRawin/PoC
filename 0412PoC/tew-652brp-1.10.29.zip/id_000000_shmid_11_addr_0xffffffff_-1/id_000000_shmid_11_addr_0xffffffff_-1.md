https://www.trendnet.com/langen/support/support-detail.asp?prod=150_TEW-652BRP

漏洞名称：
Trendnet TEW-652BRP 0x40c718 命令注入漏洞

Trendnet TEW-652BRP是Trendnet公司旗下的一款路由器固件，受影响固件名称为TEW-652BRP，受影响版本为1.10.29。

tew-652brp-1.10.29
Trendnet TEW-652BRP的/sbin/httpd二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向/ntp_sync.cgi*发送构造的POST请求，控制ntp_server参数内容，在NTP同步处理流程中拼接进入shell命令并执行，从而造成任意命令执行风险。

该漏洞位于二进制文件/sbin/httpd中，在ntp_sync.cgi*对应的处理分支内，程序会在0x40c7fc处读取ntp_server参数，并在0x40c860处调用_system执行前面拼接得到的命令。由于用户可控的ntp_server参数在进入shell前没有经过过滤或转义，攻击者可以构造恶意输入触发命令注入。

攻击者可以远程发起攻击，通过向/ntp_sync.cgi*发送POST请求，并在ntp_server参数中插入恶意命令内容来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了patch后的rehost镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/tew-652brp-1.10.29.zip/tew-652brp-1.10.29.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/ntp_sync.cgi*发送POST请求，提交ntp_server参数，使程序进入NTP同步处理分支。

第二步。该分支在0x40c7fc处读取ntp_server参数，并在后续流程中将其直接拼接进ntpclient -h %s -s -i 5 -c 1命令，再由0x40c860处的_system调用执行。由于输入内容未经过过滤，用户可控数据会进入/bin/sh -c执行路径，从而触发命令注入风险。
![alt text](image.png)
相关问题代码：

0x40c718
