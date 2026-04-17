https://www.trendnet.com/langen/support/support-detail.asp?prod=150_TEW-652BRP

漏洞名称：
Trendnet TEW-652BRP 0x40c478 栈缓冲区溢出漏洞

Trendnet TEW-652BRP是Trendnet公司旗下的一款路由器固件，受影响固件名称为TEW-652BRP，受影响版本为1.10.29。

tew-652brp-1.10.29
Trendnet TEW-652BRP的/sbin/httpd二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过向/set_sta_enrollee_pin.cgi*发送构造的POST请求，控制wps_sta_enrollee_pin参数内容，在处理WPS enrollee pin配置时将超长字符串写入栈上的固定长度缓冲区，最终导致httpd进程崩溃，并具备进一步破坏执行流的风险。

该漏洞位于二进制文件/sbin/httpd中，在do_apply_post函数处理set_sta_enrollee_pin.cgi*对应分支时，程序会在0x40c410处读取wps_sta_enrollee_pin参数，并在0x40c478处调用sprintf将其格式化写入栈上的局部缓冲区。由于这里使用的是不带长度限制的sprintf，而攻击者可控参数长度未经过有效校验，因此超长输入会覆盖后续栈内容。当前样本中，函数在执行system后返回阶段于0x40c518访问到0x61616160并触发SIGSEGV，说明栈帧已经被破坏。

攻击者可以远程发起攻击，通过向/set_sta_enrollee_pin.cgi*发送POST请求，并在wps_sta_enrollee_pin参数中放入超长字符串来触发漏洞。当前样本请求中该参数由大量'a'字符组成，已经能够稳定覆盖栈上数据并导致崩溃。

漏洞研究环境：

通过模拟仿真进行验证。当前固件目录中保留了对应样本的分析材料、原始请求和发送脚本，可用于复现该问题。

通过greenhouse进行仿真，greenhouse链接为https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
当前固件目录下包含对应的rehost压缩包tew-652brp-1.10.29.tar.gz，可结合样本目录中的send.py和packet_1.request.raw进行验证。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向/set_sta_enrollee_pin.cgi*发送POST请求，提交超长的wps_sta_enrollee_pin参数，使程序进入STA enrollee pin设置分支。

第二步。该分支在0x40c410处调用get_cgi读取wps_sta_enrollee_pin参数，并在0x40c478处按照格式串wsc_cfg pin %s调用sprintf写入栈缓冲区。由于输入长度不受限制，超长参数会覆盖保存的寄存器和返回现场。随后程序虽然继续调用system执行拼接后的命令，但在函数尾声恢复栈帧时于0x40c518触发崩溃，且崩溃地址0x61616160与输入中的'a'字节模式一致，能够证明这是由栈溢出引起的异常。
![alt text](image.png)

相关问题代码：

0x40c478
