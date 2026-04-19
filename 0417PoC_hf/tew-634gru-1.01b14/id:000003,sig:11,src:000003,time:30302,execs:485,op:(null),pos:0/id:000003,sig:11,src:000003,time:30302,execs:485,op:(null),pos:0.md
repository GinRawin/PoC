https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 0x407e98 空指针解引用漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 `/sbin/httpd` 二进制文件中存在一个 `空指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。httpd_main 在处理扩展名时直接对 strchr(path, '.') 的返回值加一并传给后续比较函数，没有检查路径是否包含 .，导致对地址 0x1 的非法访问。

该漏洞位于二进制文件 `/sbin/httpd` 中。程序在 `/sbin/httpd httpd_main 0x407ab8` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/sbin/httpd httpd_main 0x407e98` 处进入危险操作，最终导致进程崩溃并造成拒绝服务。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。httpd_main 解析请求行，把请求目标放入栈上的路径 token，并在 0x407ab8 去掉前导 /，得到 s2 = "vct_lan_00"。

第二步。httpd_main 通过 CGI 表命中 vct_lan_00 对应处理函数，trace 显示进入 do_apply_post，说明该请求确实沿着 POST CGI 路径执行。

第三步。返回 httpd_main 后执行扩展名判断：strchr(s2, '.') 返回 NULL，代码仍执行 a0 = v0 + 1 并在 0x407e98 调用比较函数，最终访问 0x00000001 触发 SIGSEGV。

相关问题代码：

0x407e98
