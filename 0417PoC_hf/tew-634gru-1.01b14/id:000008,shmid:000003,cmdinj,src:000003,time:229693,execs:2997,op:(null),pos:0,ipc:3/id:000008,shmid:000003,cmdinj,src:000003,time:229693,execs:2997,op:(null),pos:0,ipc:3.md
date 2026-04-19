https://www.trendnet.com/support/support-detail.asp?prod=180_TEW-634GRU

漏洞名称：
Trendnet TEW-634GRU 1.01B14 system 命令注入漏洞

Trendnet TEW-634GRU 1.01B14 是 Trendnet 公司旗下的一款路由器固件，受影响产品为 TEW-634GRU，受影响版本为 1.01B14。

Trendnet TEW-634GRU 1.01B14 的 `/sbin/httpd` 二进制文件中存在一个 `命令注入` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。httpd 将 POST body 中的 wps_sta_enrollee_pin 原样格式化进 "wsc_cfg pin %s"，随后通过 _system 交给 /bin/sh -c 执行，未做任何转义或去 shell 化处理。

该漏洞位于二进制文件 `/sbin/httpd` 中。程序在 `/sbin/httpd set_sta_enrollee_pin@0x424184` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/sbin/httpd set_sta_enrollee_pin@0x424184` 处进入危险操作，最终导致任意命令执行风险。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包 packet_1.request.raw 与发送脚本 send.py，可用于复现该问题；原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。POST 请求命中 set_sta_enrollee_pin.cgi*，httpd 将 body.wps_sta_enrollee_pin 作为 handler 参数传入 set_sta_enrollee_pin

第二步。set_sta_enrollee_pin 在 0x424204 将该值拼接为命令字符串 wsc_cfg pin %s

第三步。set_sta_enrollee_pin 在 0x424230 调用 _system，trace 实际观测到 /bin/sh -c "wsc_cfg pin <attacker-data>"，随后样本中的超长参数触发异常并出现 SIGSEGV

相关问题代码：

system
