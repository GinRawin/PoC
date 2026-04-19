https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/wndrmac-1.0.0.10/wndrmac-1.0.0.10.tar.gz

漏洞名称：
Netgear WNDRMAC 1.0.0.10 0x40ceac 空指针解引用漏洞

Netgear WNDRMAC 1.0.0.10 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 WNDRMAC，受影响版本为 1.0.0.10。

Netgear WNDRMAC 1.0.0.10 的 `/usr/sbin/uhttpd` 二进制文件中存在一个 `空指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。handle_request() 在未收到 Host 头时让 s7 保持 NULL，随后在 dns_hijack 分支把它作为 strstr() 第一个参数使用，导致空指针解引用崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。程序在 `/usr/sbin/uhttpd sym.handle_request 0x40cad0` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/usr/sbin/uhttpd sym.handle_request 0x40ceac` 处进入危险操作，最终导致进程崩溃并造成拒绝服务。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/wndrmac-1.0.0.10/wndrmac-1.0.0.10.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。handle_request() 读取并拆分请求行，初始化 s7 = NULL，随后解析 URL 到栈变量。

第二步。当前数据包没有 Host 头，所以 0x40cad0 这条 move s7, s0 不会执行，s7 一直保持 NULL。

第三步。代码进入 dns_hijack 检查分支后执行 strstr(s7, "routerlogin.net")，对空指针解引用并触发 SIGSEGV。

相关问题代码：

0x40ceac
