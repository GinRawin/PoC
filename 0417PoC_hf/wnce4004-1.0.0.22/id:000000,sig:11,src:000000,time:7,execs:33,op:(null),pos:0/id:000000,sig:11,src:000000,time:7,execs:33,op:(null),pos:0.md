https://www.downloads.netgear.com/files/GDC/WNCE4004/WNCE4004-V1.0.0.22.zip

漏洞名称：
Netgear WNCE4004 handle_request Host缺失导致的空指针解引用漏洞

Netgear WNCE4004 1.0.0.22 是 Netgear 公司旗下的一款无线网桥固件，受影响产品为 WNCE4004，受影响版本为 1.0.0.22。

Netgear WNCE4004 1.0.0.22 的 /usr/sbin/uhttpd 二进制文件中存在一个空指针解引用漏洞。远程攻击者可以构造异常的 GET 请求，在请求中省略 Host 请求头，并访问会触发 Host 校验逻辑的 URI，使程序在 handle_request 函数内对空指针执行 strstr，最终导致 uhttpd 进程崩溃，从而造成拒绝服务。

该漏洞位于二进制文件 /usr/sbin/uhttpd 中，在 handle_request 函数内，程序会解析 HTTP 请求头，并仅在匹配到 Host: 字段时才更新保存主机名的指针。本样本请求方法为 GET，请求路径为 /apply.cgi?...，且请求头中没有 Host 字段，导致该指针保持为 NULL。随后程序继续进入基于 URI 的 host 检查分支，在 0x404f74 处调用 strstr(s4, "mywifiext.net")，最终触发 SIGSEGV。

攻击者可以远程发起攻击，通过向目标设备发送不带 Host 请求头的恶意 GET 请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前分析基于 greenhouse 仿真环境中的 WNCE4004 1.0.0.22 固件镜像完成。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建方式可参考其 MANUAL 文档。当前样本目录中的现有 trace、容器日志和请求报文已经能够闭合本次崩溃路径。

目标配置情况：

未进行特殊配置，使用默认仿真环境启动即可复现。

具体验证过程：

第一步。攻击者向设备发送 GET 请求，请求路径为 /apply.cgi? 开头的动态资源路径，请求中不包含 Host 请求头。

第二步。uhttpd 在 handle_request 中读取请求行和请求头，程序会逐项扫描 Authorization、Content-Length、Accept-Language、SOAPAction、Host 等字段，但由于当前请求中缺少 Host，请求头对应的主机名指针始终没有被赋值，保持为 NULL。
![alt text](image.png)

第三步。程序完成方法和 URI 检查后，继续进入基于主机名的匹配逻辑。在 0x404f74 处调用 strstr 对 Host 内容与字符串 "mywifiext.net" 进行匹配，由于第一个参数为 NULL，最终触发空指针解引用并导致 uhttpd 进程崩溃。
![alt text](image-1.png)

相关问题代码：

handle_request
