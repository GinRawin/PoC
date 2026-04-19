https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/190/ids/36.html
https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/t6-v3-v4.1.5cu.748-b20211015/t6-v3-v4.1.5cu.748-b20211015.tar.gz

漏洞名称：
TOTOLINK T6 V3 4.1.5cu.748-B20211015 0x408950 NULL 指针解引用导致的拒绝服务漏洞

TOTOLINK T6 V3 4.1.5cu.748-B20211015 是 TOTOLINK 公司旗下的一款网络设备固件，受影响产品为 T6 V3，受影响版本为 4.1.5cu.748-B20211015。

TOTOLINK T6 V3 4.1.5cu.748-B20211015 的 `/bin/lighttpd` 二进制文件中存在一个 `NULL 指针解引用导致的拒绝服务` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。lighttpd 的自定义请求处理函数在未校验 request+0x20c 是否为 NULL 的情况下，直接解引用并将其与 "captive.apple.com" 比较；攻击者只需让 URI 不命中白名单分支，同时让该 Host/authority 类指针保持为空，即可触发崩溃。

该漏洞位于二进制文件 `/bin/lighttpd` 中。程序在 `/bin/lighttpd 0x408950 0x4089dc(读取 request+0x140) 0x430900` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/bin/lighttpd 0x408950 0x408b08 0x408950` 处进入危险操作，最终导致安全风险。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

原始固件可通过上述官方链接获取。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/t6-v3-v4.1.5cu.748-b20211015/t6-v3-v4.1.5cu.748-b20211015.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。入口二进制 lighttpd 解析 HTTP 请求并为 Host/authority 类字段保留 request+0x20c 这个槽位，相关映射指令位于 0x430934。

第二步。请求处理流程走到 0x40d944 -> 0x408950，先从 request+0x140 读取路径字符串；/phone 不匹配 .asp、.html、.htm、config.dat、/login/login.cgi，因此控制流落到 0x408b00。

第三步。0x408b04 读取 request+0x20c，0x408b08 继续解引用 *(request->field_0x20c)；该指针为 NULL，因此立即触发 SIGSEGV。

相关问题代码：

0x408950
