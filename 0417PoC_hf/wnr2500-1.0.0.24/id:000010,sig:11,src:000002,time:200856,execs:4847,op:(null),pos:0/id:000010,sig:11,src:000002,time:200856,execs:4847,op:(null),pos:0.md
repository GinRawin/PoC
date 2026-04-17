漏洞名称：
Netgear WNR2500 0x40dfcc 栈缓冲区溢出漏洞

Netgear WNR2500是Netgear公司旗下的一款路由器固件，受影响固件名称为WNR2500，受影响版本为1.0.0.24。

wnr2500-1.0.0.24
Netgear WNR2500的/usr/sbin/uhttpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的GET请求，使程序在处理`.htm`类页面请求时将超长path直接写入栈上固定缓冲区，覆盖返回地址并导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。程序在handle_request中解析请求行后，会把请求path放入静态页面分发表进行匹配。当前样本的请求路径以`.html`开头，能够命中通用`.htm`表项，并进入处理函数0x40dfcc。该函数在0x40e01c处调用`sprintf(sp+0x3c, "/www/%s", path)`，把攻击者可控的超长path写入局部栈缓冲区，没有长度检查。溢出破坏了保存的返回地址，函数在尾声返回时跳转到被污染的地址`0x61616160`并崩溃。

攻击者可以远程发起攻击，通过向设备发送包含超长`.html`路径的GET请求来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经patch了认证环节之后的，未patch的环境可以用binwalk解压对应下载链接的固件得到。
原始固件链接为：https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/IMG_wnr2500-1.0.0.24.zip

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了rehost的镜像，链接为https://github.com/GinRawin/PoC/blob/main/0412PoC/wnr2500-1.0.0.24.zip/wnr2500-1.0.0.24.tar.gz，启动的命令为进入到dockerfile目录下，然后docker-compose build, docker-compose up。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者发送GET请求，请求行中的path形如`/upgrade.cgi.html...`。handle_request使用strsep解析出path后，在静态页面分发表中对每个表项执行`strstr(path, entry_name)`。由于超长路径开头包含`.html`，因此命中了通用`.htm`表项，并转入处理函数0x40dfcc。
![alt text](image.png)

第二步。处理函数0x40dfcc在0x40e01c处调用`sprintf("/www/%s", path)`，把整个超长路径写入位于`sp+0x3c`的栈缓冲区。该缓冲区大小固定，无法容纳当前样本中的长字符串，所以溢出继续覆盖栈帧中的保存返回地址。
![alt text](image-1.png)

第三步。函数执行到尾声0x40e33c附近时，从栈中恢复出已经被攻击字符串覆盖的返回地址，最终跳转到`0x61616160`并触发SIGSEGV。崩溃地址中的`0x61`模式与请求中的大量`a`字符一致，能够证明本次现象由栈溢出直接导致。
![alt text](image-2.png)

相关问题代码：

0x40dfcc
