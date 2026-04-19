https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/190/ids/36.html
https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/t6-v3-v4.1.5cu.748-b20211015/t6-v3-v4.1.5cu.748-b20211015.tar.gz

漏洞名称：
TOTOLINK T6 V3 4.1.5cu.748-B20211015 strcpy 栈缓冲区溢出漏洞

TOTOLINK T6 V3 4.1.5cu.748-B20211015 是 TOTOLINK 公司旗下的一款网络设备固件，受影响产品为 T6 V3，受影响版本为 4.1.5cu.748-B20211015。

TOTOLINK T6 V3 4.1.5cu.748-B20211015 的 `/bin/lighttpd` 二进制文件中存在一个 `栈缓冲区溢出` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。代码把可控的 Host 字符串直接 strcpy 到栈上 256 字节缓冲区 s8+124，超长输入覆盖了同一栈帧中的保存参数，随后被污染的连接指针传入 0x40b30c 并在 0x40b348 解引用时触发 SIGSEGV。

该漏洞位于二进制文件 `/bin/lighttpd` 中。程序在 `/bin/lighttpd 0x40c1f0 0x40c2cc-0x40c2d4 (从连接对象偏移 0x110 取出 Host 字符串指针) 0x40c1f0` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/bin/lighttpd 0x40c1f0 0x40c2e4 (调用 0x404980 -> strcpy) 0x40c1f0` 处进入危险操作，最终导致栈破坏并触发进程崩溃。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/t6-v3-v4.1.5cu.748-b20211015/t6-v3-v4.1.5cu.748-b20211015.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。0x40c1f0 先遍历白名单页面名，对 *(conn + 0x140) 做 strstr 检查；当前请求路径不命中白名单，继续执行。

第二步。0x40c2cc-0x40c2e4 取出 *(conn + 0x110) 指向的 Host 字符串，调用 strcpy 复制到栈缓冲区 s8+124。

第三步。超长 Host 覆盖栈上的保存参数；返回后 0x40c2ec 读出被污染的 a0 传入 0x40b30c，0x40b348 再解引用该伪造指针并在 si_addr=0x616162d9 处崩溃。

相关问题代码：

strcpy
