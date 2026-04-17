漏洞名称：
Tenda AP5 /cgi-bin/upgrade 接口上传解析栈缓冲区溢出漏洞

Tenda AP5是Tenda公司旗下的一款无线接入点设备，受影响固件名称为us-ap5v1.0br-v1.0.0.9-2224-en-tde01，受影响版本为V1.0.0.9(2224)。

us-ap5v1.0br-v1.0.0.9-2224-en-tde01
Tenda AP5的`/bin/httpd`二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过向`/cgi-bin/upgrade`发送构造的POST请求触发上传解析流程，使程序在`webCgiGetUploadFile()`中将非multipart格式的JSON请求体逐字节写入固定长度的栈缓冲区，且写入过程缺少边界检查，最终越界覆盖上层调用栈中的关键局部变量，并在后续解引用被污染指针时导致`httpd`进程崩溃，造成拒绝服务。

该漏洞位于二进制文件`/bin/httpd`中，关键调用链可概括为`webs_Tenda_CGI_BIN_Handler -> upgrade -> webCgiGetUploadFile`。其中`webs_Tenda_CGI_BIN_Handler()`根据请求路径将请求分派到`upgrade()`；`upgrade()`创建并映射`/var/image`后，将映射地址指针传入`webCgiGetUploadFile()`；后者在处理当前样本对应的JSON请求体时，于`0x433e38`附近执行逐字节复制，将可控数据从读取缓冲区写入位于`sp+0x845`的栈缓冲区。由于该缓冲区到栈帧末尾仅剩约83字节，而样本请求体长度为259字节，写入会跨越当前函数栈帧并覆写调用者`upgrade()`中的局部变量`mapped_addr`。在后续执行到`0x43410c`附近时，程序对该已被污染的指针进行解引用，最终触发`SIGSEGV`。从崩溃地址`0x72657375`可以看出，该值与请求体中可控字符串`"user"`的ASCII字节一致，说明崩溃由请求内容直接影响。

攻击者可以远程发起攻击，通过向`/cgi-bin/upgrade`发送带有`Content-Type: application/json`和超长JSON请求体的POST请求来触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中已提供触发请求`packet_1.request.raw`以及发送脚本`send.py`，可直接用于向仿真中的目标`httpd`发送原始HTTP报文。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向`/cgi-bin/upgrade`发送POST请求，请求头中指定`Content-Type: application/json`和`Content-Length: 259`，请求体为单行JSON数据。该请求会命中`/cgi-bin/upgrade`处理路径并进入`webs_Tenda_CGI_BIN_Handler()`。
![alt text](image.png)

第二步。`webs_Tenda_CGI_BIN_Handler()`根据URI将请求分派给`upgrade()`。`upgrade()`随后创建`/var/image`，按请求体长度扩展文件并执行`mmap`，将返回的映射地址保存在局部变量`mapped_addr`中，然后调用`webCgiGetUploadFile(req, &mapped_addr)`继续处理上传数据。
![alt text](image-1.png)

第三步。进入`webCgiGetUploadFile()`后，函数先在`0x433d10`附近将请求体读入自身栈上的输入缓冲区`sp+0x44`。随后函数并未验证当前数据是否为合法multipart上传内容，而是在`0x433e1c-0x433e38`附近进入逐字节复制逻辑，将输入缓冲区中的内容写入位于`sp+0x845`的目标缓冲区。由于这里没有对写入长度做上界限制，来自请求体的259字节数据会超过该栈缓冲区实际可用空间，并越界覆盖到上层调用者`upgrade()`的栈槽。
![alt text](image-2.png)
![alt text](image-3.png)

第四步。越界写发生后，`upgrade()`栈中的`mapped_addr`被请求体中的可控字节污染。结合当前样本，崩溃时的`si_addr=0x72657375`对应ASCII字符串`"user"`，与请求体中`sys.username`、`sys.baseusername`、`sys.userpass`等字段包含的文本相吻合，说明该指针值来自攻击者输入。随后程序在`0x43410c`附近继续通过该指针取值并发生非法访问，最终导致`httpd`进程崩溃。
![alt text](image-4.png)

第五步。由于崩溃发生在HTTP请求处理线程中，攻击者可通过反复发送该类请求稳定触发`httpd`异常退出，从而形成拒绝服务影响。依据当前样本已有分析材料，可以确认崩溃来源于真实的越界写和后续受控指针解引用，而非单纯仿真噪声或偶发错误。

相关问题代码：

`webs_Tenda_CGI_BIN_Handler`

`upgrade`

`webCgiGetUploadFile`
