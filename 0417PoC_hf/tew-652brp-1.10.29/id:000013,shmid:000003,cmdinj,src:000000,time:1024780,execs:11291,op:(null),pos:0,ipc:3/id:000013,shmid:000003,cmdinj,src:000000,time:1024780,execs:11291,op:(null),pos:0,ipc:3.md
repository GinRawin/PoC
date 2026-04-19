https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/tew-652brp-1.10.29/tew-652brp-1.10.29.tar.gz

漏洞名称：
Trendnet TEW-652BRP 1.10.29 sprintf 栈缓冲区溢出漏洞

Trendnet TEW-652BRP 1.10.29 是 Trendnet 公司旗下的一款网络设备固件，受影响产品为 TEW-652BRP，受影响版本为 1.10.29。

Trendnet TEW-652BRP 1.10.29 的 `/sbin/httpd` 二进制文件中存在一个 `栈缓冲区溢出` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。httpd 从 POST 参数 wps_sta_enrollee_pin 读取攻击者可控字符串后，使用 sprintf 将其格式化到仅 32 字节的栈缓冲区 sp+0x18，导致返回现场被覆盖并在函数尾声崩溃。

该漏洞位于二进制文件 `/sbin/httpd` 中。程序在 `/sbin/httpd do_apply_post@@Base 0x40c410` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/sbin/httpd do_apply_post@@Base 0x40c478` 处进入危险操作，最终导致栈破坏并触发进程崩溃。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/tew-652brp-1.10.29/tew-652brp-1.10.29.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。POST 请求命中 set_sta_enrollee_pin.cgi*，httpd 进入对应处理路径。

第二步。do_apply_post 在 0x40c410 读取 wps_sta_enrollee_pin，并在 0x40c478 用格式串 wsc_cfg pin %s 将其写入栈上的命令缓冲区。

第三步。该命令随后被 system 执行；函数返回时栈帧已被覆盖，在 0x40c518 访问到 0x61616160 并触发 SIGSEGV。

相关问题代码：

sprintf
