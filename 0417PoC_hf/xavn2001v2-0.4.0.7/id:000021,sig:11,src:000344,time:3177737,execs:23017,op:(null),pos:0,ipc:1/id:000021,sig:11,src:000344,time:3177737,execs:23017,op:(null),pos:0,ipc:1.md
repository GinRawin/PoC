漏洞名称：
Netgear XAVN2001v2 plc_dev_select_num参数缺失导致空指针解引用漏洞（样本id:000021）

Netgear XAVN2001v2是Netgear公司旗下的一款网络设备固件，受影响固件名称为XAVN2001v2，受影响版本为0.4.0.7。

xavn2001v2-0.4.0.7
Netgear XAVN2001v2的/usr/sbin/uhttpd二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向/apply.cgi发送特制POST请求，使程序在PLC设备配置处理路径中读取缺失的`plc_dev_select_num`字段，并在未做判空的情况下直接传给atoi，最终导致uhttpd进程崩溃，造成拒绝服务。

该漏洞位于二进制文件/usr/sbin/uhttpd中。在处理/apply.cgi请求时，程序会根据`submit_flag`选择具体的配置处理分支。当前样本中，`submit_flag=plc_dev_config`使程序进入0x0043155c对应的PLC设备配置函数。该函数在0x004315b0调用cgi_value读取`plc_dev_select_num`字段，但当前请求中没有该字段，因此cgi_value返回NULL。随后程序在0x004315c0将该返回值放入a0，并在0x004315d4直接调用atoi，从而触发空指针解引用崩溃。

攻击者可以远程发起攻击，通过发送包含`submit_flag=plc_dev_config`但缺失`plc_dev_select_num`参数的POST请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中已经包含入口trace、uhttpd trace和容器日志，可以对应出从字段缺失到atoi崩溃的完整控制流。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/apply.cgi发送POST请求，并将`submit_flag`设置为`plc_dev_config`。程序在CGI参数处理阶段根据该值进入PLC设备配置分支。
![alt text](image.png)

第二步。PLC设备配置函数在0x004315b0调用cgi_value读取`plc_dev_select_num`，但该字段在当前请求中缺失，因此返回值为NULL。程序随后没有检查该返回值是否为空，而是直接将其作为atoi的输入参数。
![alt text](image-1.png)

第三步。0x004315d4处对atoi的调用使用了空指针参数，trace末尾出现`si_addr=NULL`，日志中也记录到SIGSEGV。这表明漏洞根因是缺失字段引发的空指针解引用。
![alt text](image-2.png)

相关问题代码：

0x0043155c
