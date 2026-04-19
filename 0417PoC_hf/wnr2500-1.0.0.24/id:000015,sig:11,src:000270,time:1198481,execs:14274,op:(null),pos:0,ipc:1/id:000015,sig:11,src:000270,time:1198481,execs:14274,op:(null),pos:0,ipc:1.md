https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/wnr2500-1.0.0.24/wnr2500-1.0.0.24.tar.gz

漏洞名称：
Netgear WNR2500 1.0.0.24 strstr NULL 指针解引用漏洞

Netgear WNR2500 1.0.0.24 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 WNR2500，受影响版本为 1.0.0.24。

Netgear WNR2500 1.0.0.24 的 `/usr/sbin/uhttpd` 二进制文件中存在一个 `NULL 指针解引用` 漏洞。远程攻击者可以通过发送构造的 HTTP 请求触发该问题。handle_request 在 URI 中找不到 ? 时把“查询串指针”写成 NULL，后续 restore.cgi 回调 0x405344 未判空直接把该指针作为 strstr() 第一个实参传入，导致 SIGSEGV。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。程序在 `/usr/sbin/uhttpd handle_request@0x407660 0x407660` 处对攻击者可控输入完成读取、解析或传递，并最终在 `/usr/sbin/uhttpd restore.cgi主回调 0x405344` 处进入危险操作，最终导致安全风险。

攻击者可以远程发起攻击，通过向目标设备发送恶意请求触发漏洞。

漏洞研究环境：

通过模拟仿真进行验证。当前样本目录中提供了对应的请求包与发送脚本 send.py，可用于复现该问题。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0417PoC_hf/wnr2500-1.0.0.24/wnr2500-1.0.0.24.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。handle_request 解析 POST /restore.cgi HTTP/1.1，把路径规范化为 restore.cgi，随后在 0x408304 调用 strchr(s1, '?') 检查 query。

第二步。由于请求 URI 不含 ?，分支落到 0x40832c，延迟槽 0x40831c 已把 [sp+0x20] 写成 NULL；之后路由匹配命中 restore.cgi 表项并调用其预处理函数 0x40689c。

第三步。0x408b04 从 [sp+0x20] 重新取回 s1=NULL，0x408b50 间接调用 restore.cgi 主回调 0x405344；该回调的首个外部调用是 0x405378 -> strstr(a0=NULL, a1=0x45b9dc)，立即触发 SIGSEGV。

相关问题代码：

strstr
