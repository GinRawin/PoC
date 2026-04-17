漏洞名称：
Netgear WNR2500 0x405344 空指针解引用漏洞

Netgear WNR2500是Netgear公司旗下的一款路由器固件，受影响固件名称为WNR2500，受影响版本为1.0.0.24。

wnr2500-1.0.0.24
Netgear WNR2500的/usr/sbin/uhttpd二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向`/restore.cgi`发送不带查询串的POST请求，使程序在后续restore.cgi回调中把空的query指针直接传给`strstr`，最终导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。程序在handle_request中解析`POST /restore.cgi HTTP/1.1`后，会尝试通过`strchr(uri, '?')`提取查询串起始位置。当前样本的URI不包含`?`，因此该逻辑把保存于栈槽`[sp+0x20]`中的query指针写成NULL。之后路由匹配命中`restore.cgi`表项，并进入主回调0x405344。该回调在0x405378处直接执行`strstr(a0, a1)`，其中第一个参数正是前面得到的空query指针，于是触发SIGSEGV。

攻击者可以远程发起攻击，通过向`/restore.cgi`发送不包含查询串的POST请求来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。
原始固件链接为：https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/IMG_wnr2500-1.0.0.24.zip

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/wnr2500-1.0.0.24.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送`POST /restore.cgi HTTP/1.1`请求。handle_request在解析URI后，会调用`strchr(uri, '?')`查找查询串起始位置。由于当前请求URI中根本不包含`?`，因此这一查找结果为NULL，并被写入后续共用的query指针槽位。
![alt text](image.png)

第二步。程序继续按照静态路由表匹配`restore.cgi`，并在预处理之后进入主回调0x405344。进入该回调时，之前保存在栈上的query指针又被重新取回，并作为第一个实参传入后续字符串搜索逻辑。
![alt text](image-1.png)

第三步。0x405344在0x405378处直接调用`strstr(NULL, needle)`，字符串库内部对空指针解引用，最终触发SIGSEGV。trace中`0x408304 -> 0x40832c -> 0x408b4c -> 0x405344`这一链条可以直接证明，崩溃由“无查询串URI”触发，而不是POST body中的其他字段导致。
![alt text](image-2.png)

相关问题代码：

0x405344
