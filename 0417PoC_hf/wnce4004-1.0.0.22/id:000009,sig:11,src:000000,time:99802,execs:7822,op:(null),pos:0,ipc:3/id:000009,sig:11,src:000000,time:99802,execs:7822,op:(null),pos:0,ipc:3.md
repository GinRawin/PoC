https://www.downloads.netgear.com/files/GDC/WNCE4004/WNCE4004-V1.0.0.22.zip

漏洞名称：
Netgear WNCE4004 upgrade_check.cgi 请求处理中的未初始化变量使用漏洞

Netgear WNCE4004 1.0.0.22 是 Netgear 公司旗下的一款无线网桥固件，受影响产品为 WNCE4004，受影响版本为 1.0.0.22。

Netgear WNCE4004 1.0.0.22 的 /usr/sbin/uhttpd 二进制文件中存在一个未初始化变量使用漏洞。远程攻击者可以构造访问 /upgrade_check.cgi 的异常 GET 请求，在未提供 Content-Length 和请求体的情况下进入升级处理逻辑，使 get_postfile 使用未初始化的局部变量参与栈地址计算，最终触发非法访问并导致进程崩溃。

该漏洞位于二进制文件 /usr/sbin/uhttpd 中。程序在 handle_request 中解析请求头时，会将 Content-Length 解析结果保存到长度变量 s6，而该变量在没有匹配到 Content-Length 时保持初始值 0。本样本请求访问 /upgrade_check.cgiGetInfo?，请求没有有效的 Content-Length 和 body，但仍然命中升级处理逻辑，随后在 0x4072e8 处调用 get_postfile("/tmp/uhttp-upgrade.img", s2, s6)。进入 get_postfile 后，当长度参数小于等于 0 时，程序走入未初始化分支，在 0x406aec 附近对基于未初始化 s0 计算出的地址执行读操作，最终触发 SIGSEGV。

攻击者可以远程发起攻击，通过发送不携带有效请求体长度的升级检查 GET 请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前分析基于 greenhouse 仿真环境中的 WNCE4004 1.0.0.22 固件镜像完成。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。当前样本目录中的 trace 同时记录了 uhttpd 主进程、升级处理函数以及由 system 命令派生出的子进程路径，足以确认真实崩溃发生在 get_postfile 内部。

目标配置情况：

未进行特殊配置，使用默认仿真环境启动即可复现。

具体验证过程：

第一步。攻击者向设备发送 GET 请求，请求目标为 /upgrade_check.cgiGetInfo?，并且不提供有效的 Content-Length 和请求体内容。

第二步。uhttpd 在 handle_request 中解析请求后，识别出升级检查路径，并进入相应的升级处理函数。由于当前请求没有被正确解析出 Content-Length，对应长度变量保持为 0，并被继续传入 get_postfile。
![alt text](image.png)

第三步。get_postfile 在长度参数小于等于 0 的分支中没有正确初始化内部索引变量，却继续基于该变量计算栈上地址并进行读取，最终在 0x406aec 附近访问非法地址并触发 SIGSEGV，导致 uhttpd 进程崩溃。
![alt text](image-1.png)

相关问题代码：

handle_request
get_postfile
