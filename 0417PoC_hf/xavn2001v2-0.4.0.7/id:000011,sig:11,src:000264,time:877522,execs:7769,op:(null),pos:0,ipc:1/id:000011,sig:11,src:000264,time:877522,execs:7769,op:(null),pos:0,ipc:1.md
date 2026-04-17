漏洞名称：
Netgear XAVN2001v2 device_name参数缺失导致空指针解引用漏洞（样本id:000011）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向/apply.cgi发送特制POST请求，在submit_flag命中`ether`处理分支后故意缺失`device_name`字段，使程序把空指针作为源参数传给strcpy，最终导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理/apply.cgi请求时，cgi_setobject会先读取`submit_flag`参数，并根据其值选择具体的配置处理函数。当前样本中，`submit_flag=ether`使程序进入0x004355d8对应的ether处理函数。该函数在0x00435618调用cgi_value读取`device_name`字段，但由于该字段在请求中缺失，cgi_value返回NULL。随后程序在0x0043562c直接调用strcpy，并在delay slot的0x00435630把NULL设置为源参数，导致`strcpy(dst, NULL)`触发空指针解引用崩溃。

攻击者可以远程发起攻击，通过向/apply.cgi发送包含`submit_flag=ether`但不提供`device_name`字段的POST请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中保留了trace、日志以及相关分析材料，足以还原字段缺失到崩溃发生的完整链路。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/apply.cgi发送POST请求，令程序进入CGI配置路径。cgi_setobject首先读取`submit_flag`，并在分发表中匹配到`ether`对应的处理函数0x004355d8。
![alt text](image.png)

第二步。ether处理函数调用cgi_value读取`device_name`字段，但该字段在当前样本中缺失，因此cgi_value返回NULL。随后程序没有进行判空，而是直接准备调用strcpy，将返回值作为源字符串使用。
![alt text](image-1.png)

第三步。0x0043562c处的strcpy在源参数为NULL的情况下执行，trace末尾显示`si_addr=NULL`，容器日志也记录到SIGSEGV。这说明该漏洞是由缺失字段触发的真实空指针解引用，而不是仿真噪声。
![alt text](image-2.png)

相关问题代码：

0x004355d8
