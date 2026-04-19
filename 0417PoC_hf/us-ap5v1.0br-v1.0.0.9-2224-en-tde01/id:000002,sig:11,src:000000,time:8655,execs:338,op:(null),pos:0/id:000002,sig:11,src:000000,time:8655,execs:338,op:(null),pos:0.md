https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/us-ap5v1.0br-v1.0.0.9-2224-en-tde01/us-ap5v1.0br-v1.0.0.9-2224-en-tde01.tar.gz

漏洞名称：
Tenda AP5 1.0.0.9-2224-EN-TDE01 0x433e38 栈缓冲区溢出漏洞

Tenda AP5 1.0.0.9-2224-EN-TDE01 是 Tenda 公司旗下的一款网络设备固件，受影响产品为 AP5，受影响版本为 1.0.0.9-2224-EN-TDE01。

Tenda AP5 1.0.0.9-2224-EN-TDE01 的 `bin/httpd` 二进制文件中存在一个 `栈缓冲区溢出` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。upgrade() 在处理 POST /cgi-bin/upgrade 时调用 webCgiGetUploadFile() 解析上传内容，但该函数把非 multipart 的单行 JSON 请求体逐字节写入仅 83 字节的栈缓冲区 sp+0x845，无边界检查，越界后覆盖了调用者 upgrade() 栈里的 mmap 返回指针，最终在 0x43410c 解引用被污染指针 0x72657375("user") 崩溃。

该漏洞位于二进制文件 `bin/httpd` 中。程序在 `bin/httpd webCgiGetUploadFile 0x433d10 0x433d10` 处对攻击者可控输入完成读取、解析或传递，并最终在 `bin/httpd webCgiGetUploadFile 0x433e38 0x433e38` 处进入危险操作，最终导致栈破坏并触发进程崩溃。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/us-ap5v1.0br-v1.0.0.9-2224-en-tde01/us-ap5v1.0br-v1.0.0.9-2224-en-tde01.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。webs_Tenda_CGI_BIN_Handler() 根据 URL 命中 upgrade()。

第二步。upgrade() 创建 /var/image，按 Content-Length 扩展文件并 mmap，然后把 &mapped_addr 传给 webCgiGetUploadFile()。

第三步。webCgiGetUploadFile() 在 0x433d10 读入请求体，在 0x433e38 无界复制导致栈溢出，随后在 0x43410c 解引用被改写的 mapped_addr 并因 0x72657375 崩溃。

相关问题代码：

0x433e38
