http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 config_wladv_plc 空指针解引用漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向 `/apply.cgi` 发送构造的 POST 请求触发该问题。程序根据 `submit_flag=wlan_adv_plc` 进入 `config_wladv_plc` 处理流程后，会调用 `cgi_value("wl_enable_LED", ...)` 读取表单字段，但在字段缺失时没有对返回值进行判空，而是直接将该指针传入 `strcmp`，最终导致 `uhttpd` 进程崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。请求在 `cgi_setobject` 中读取 `submit_flag` 并命中 `wlan_adv_plc` 对应的处理函数 `0x437e0c`。在该函数内部，程序于 `0x437e7c` 调用 `cgi_value("wl_enable_LED", ...)`，返回值在 `0x437e90` 被保存到 `s1`。随后 `0x437ec0` 直接执行 `strcmp(s1, "off")`，当请求中缺少 `wl_enable_LED` 字段时，`s1` 为 `NULL`，从而触发空指针解引用。

攻击者可以远程发起攻击，通过向 `/apply.cgi` 提交包含 `submit_flag=wlan_adv_plc`、但缺少 `wl_enable_LED` 字段的 POST 请求触发漏洞。本样本的原始请求正文中包含 `submit_flag=wlan_adv_plc`，但没有提供目标字段，符合该漏洞条件。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 `/apply.cgi` 发送 POST 请求，并在请求体中设置 `submit_flag=wlan_adv_plc`，以便程序命中 `config_wladv_plc` 配置处理分支。该请求体中未携带 `wl_enable_LED` 参数，因此后续的 CGI 参数查找将返回空指针。
![alt text](image-1.png)
![alt text](image-2.png)

第二步。程序在 `0x437e7c` 处调用 `cgi_value("wl_enable_LED", ...)`，由于该字段缺失，返回值为 `NULL`。随后 `0x437ec0` 直接执行 `strcmp(NULL, "off")`，在字符串比较函数内部触发空指针解引用，最终导致 `uhttpd` 进程因 `SIGSEGV` 崩溃。
![alt text](image.png)

相关问题代码：

0x437ec0
