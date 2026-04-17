https://www.downloads.netgear.com/files/GDC/WNCE4004/WNCE4004-V1.0.0.22.zip

漏洞名称：
Netgear WNCE4004 静态资源路径拼接导致的栈缓冲区溢出漏洞

Netgear WNCE4004 1.0.0.22 是 Netgear 公司旗下的一款无线网桥固件，受影响产品为 WNCE4004，受影响版本为 1.0.0.22。

Netgear WNCE4004 1.0.0.22 的 /usr/sbin/uhttpd 二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过构造超长的 GET 请求路径，使程序在静态资源处理函数中将攻击者可控的路径直接拼接到栈缓冲区，覆盖保存的返回地址并导致进程崩溃，从而造成拒绝服务。

该漏洞位于二进制文件 /usr/sbin/uhttpd 中。程序在 handle_request 中解析 URL 后，会把去掉前导斜杠的路径字符串继续传递给下游资源处理函数。本样本请求访问的是 /cc.js 开头的超长路径，程序在 0x405948 处把该路径作为参数传入 0x40654c 对应的处理函数，随后在 0x406590 处执行 sprintf(sp+0x18, "/www/%s", attacker_path)。由于目标缓冲区位于栈上且缺少长度检查，超长路径覆盖了保存的寄存器和返回地址，最终在函数尾声崩溃。

攻击者可以远程发起攻击，通过发送包含超长 URL 路径的恶意 GET 请求触发该漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前分析基于 greenhouse 仿真环境中的 WNCE4004 1.0.0.22 固件镜像完成。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。当前样本目录中的 trace、控制台日志和原始请求报文能够对应到从 handle_request 到 sprintf 崩溃点的完整路径。

目标配置情况：

未进行特殊配置，使用默认仿真环境启动即可复现。

具体验证过程：

第一步。攻击者向设备发送 GET 请求，请求路径为 /cc.js 后拼接超长可控字符串，使 URI 长度远超正常静态资源请求范围。

第二步。uhttpd 解析请求行后，保留路径部分并去掉前导 /，随后将该超长路径传入对应的静态资源处理函数。该处理函数在栈上分配局部缓冲区，并使用固定格式 "/www/%s" 组织真实文件路径。
![alt text](image.png)

第三步。程序在 0x406590 处调用 sprintf 把超长路径写入栈缓冲区，没有任何长度检查。由于写入内容超过缓冲区容量，保存的返回地址被覆盖，函数返回时触发 SIGSEGV，最终导致 uhttpd 进程崩溃。
![alt text](image-1.png)

相关问题代码：

handle_request
0x40654c
