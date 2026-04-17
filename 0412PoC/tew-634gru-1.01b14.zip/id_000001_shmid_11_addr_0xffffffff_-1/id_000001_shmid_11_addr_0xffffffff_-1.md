https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 0x40c8b0 命令注入漏洞

Trendnet TEW-634GRU 1.01B14是Trendnet公司旗下的一款路由器固件，受影响产品为TEW-634GRU，受影响版本为1.01B14。

Trendnet TEW-634GRU 1.01B14的/sbin/httpd二进制文件中存在一个命令注入漏洞。远程攻击者可以通过向/ntp_sync.cgi*发送构造的POST请求，控制ntp_server参数内容，使其进入shell命令拼接流程并被/bin/sh -c执行，从而造成任意命令执行。

该漏洞位于二进制文件/sbin/httpd中，在do_apply_post函数的NTP同步处理分支内，程序在0x40c994处读取ntp_server参数，在0x40c9c4处通过sprintf将用户输入拼接进ntpclient -h %s -s -i 5 -c 1命令字符串，随后在0x40c9f8处调用_system执行该命令。由于整个过程没有对用户输入进行shell级过滤，因此攻击者可以构造恶意参数触发命令注入。

攻击者可以远程发起攻击，通过向/ntp_sync.cgi*发送包含恶意ntp_server参数的POST请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中提供了对应的rehost环境，原始固件可通过上述下载链接获取。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/tew-634gru-1.01b14.zip/tew-634gru-1.01b14.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/ntp_sync.cgi*发送POST请求，请求中携带ntp_server参数，使程序进入NTP同步处理分支。

第二步。程序在0x40c994处读取ntp_server参数内容，并在0x40c9c4处将其拼接到ntpclient -h %s -s -i 5 -c 1命令模板中。

第三步。程序在0x40c9f8处调用_system执行拼接后的命令，请求参数最终经/bin/sh -c解释执行，造成命令注入。
![alt text](image.png)
相关问题代码：

0x40c8b0
