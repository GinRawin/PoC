https://www.downloads.netgear.com/files/GDC/WNCE4004/WNCE4004-V1.0.0.22.zip

漏洞名称：
Netgear WNCE4004 .css 资源处理路径中的栈缓冲区溢出漏洞

Netgear WNCE4004 1.0.0.22 是 Netgear 公司旗下的一款无线网桥固件，受影响产品为 WNCE4004，受影响版本为 1.0.0.22。

Netgear WNCE4004 1.0.0.22 的 /usr/sbin/uhttpd 二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以构造包含 .css 标识和超长路径内容的 GET 请求，使程序在静态资源处理函数内对栈缓冲区执行无边界 sprintf，从而覆盖保存寄存器并导致进程崩溃。

该漏洞位于二进制文件 /usr/sbin/uhttpd 中。程序在 handle_request 内根据 URI 中的资源类型选择不同 handler。本样本请求路径为 /cc.css 开头，并在后续拼接超长内容，成功命中 .css 对应的 handler。程序在 0x405948 处把请求路径作为参数传入 0x406730，随后在 0x406768 处执行 sprintf(sp+0x18, "/www/%s", a0)。由于目标缓冲区长度有限，而实际写入数据超过其容量，最终造成栈溢出并在函数返回时崩溃。

攻击者可以远程发起攻击，通过发送带有超长 .css 路径的恶意 GET 请求触发该漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前分析基于 greenhouse 仿真环境中的 WNCE4004 1.0.0.22 固件镜像完成。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。当前样本目录中的日志和 trace 已能还原从 .css 匹配、handler 分发到 sprintf 栈溢出的完整过程。

目标配置情况：

未进行特殊配置，使用默认仿真环境启动即可复现。

具体验证过程：

第一步。攻击者构造 GET 请求，请求路径为 /cc.css 开头，并追加超长内容，使整个路径长度超过静态资源处理函数内部局部缓冲区的容量。

第二步。uhttpd 在 handle_request 中对 URI 进行资源类型匹配。由于当前路径中包含 .css，程序命中 .css mime handler，并把请求路径作为参数传入 0x406730 对应的静态资源处理函数。
![alt text](image.png)

第三步。该处理函数在 0x406768 处调用 sprintf(sp+0x18, "/www/%s", a0) 拼接文件路径。由于缺少长度检查，超长输入覆盖了保存的寄存器和返回地址，最终在函数尾声触发 SIGSEGV，导致 uhttpd 进程崩溃。
![alt text](image-1.png)

相关问题代码：

handle_request
0x406730
