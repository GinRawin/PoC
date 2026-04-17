https://www.trendnet.com/langen/support/support-detail.asp?prod=150_TEW-652BRP

漏洞名称：
Trendnet TEW-652BRP 0x407d98 空指针解引用漏洞

Trendnet TEW-652BRP是Trendnet公司旗下的一款路由器固件，受影响固件名称为TEW-652BRP，受影响版本为1.10.29。

tew-652brp-1.10.29
Trendnet TEW-652BRP的/sbin/httpd二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向/vct_lan_01发送构造的HTTP请求，使程序在处理该路径时对请求URL后缀执行错误判断，最终在后缀比较流程中解引用非法地址并导致httpd进程崩溃。

该漏洞位于二进制文件/sbin/httpd中，在httpd_main函数针对vct_lan_01路径的处理分支内，程序会在0x407d7c处调用strchr查找路径中的'.'字符，并在0x407d98处继续调用strncmp比较扩展名。由于传入的路径字符串不包含'.'时，strchr返回NULL，但后续代码未进行判空检查，直接将返回值加1后作为strncmp参数使用，因此会触发对非法地址0x1的访问并造成SIGSEGV。

攻击者可以远程发起攻击，通过向/vct_lan_01发送不带文件扩展名的请求来触发漏洞。当前样本中的原始请求为POST /vct_lan_01 HTTP/1.1，请求体为空，但已经足以使程序进入存在缺陷的处理路径。

漏洞研究环境：

通过模拟仿真进行验证。当前固件目录中保留了对应样本的分析材料、原始请求和发送脚本，可用于复现该问题。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
当前固件目录下包含对应的rehost压缩包tew-652brp-1.10.29.tar.gz，可结合样本目录中的send.py和packet_1.request.raw进行验证。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/vct_lan_01发送HTTP请求，使/sbin/httpd在parse_http_url_request中解析出路径字符串，并在httpd_main中命中vct_lan_01对应的处理分支。

第二步。程序在0x407d7c处对路径字符串调用strchr查找'.'字符。由于当前请求路径为/vct_lan_01，不包含扩展名，strchr返回NULL。随后代码仍在0x407d88处将该返回值加1，并在0x407d98处作为strncmp的第一个参数使用，最终访问地址0x1并触发SIGSEGV。现有trace也显示崩溃点位于该分支附近，si_addr=0x00000001，与空指针解引用结论一致。
![alt text](image.png)

相关问题代码：

0x407d98
