http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 wlan_g1_a1 空指针解引用漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个空指针解引用漏洞。远程攻击者可以通过向 `/apply.cgi` 发送构造的 POST 请求触发该问题。程序在根据 `submit_flag=wlan_g1_a1` 进入 guest wireless 配置处理逻辑后，会读取字段 `wlg_guest_endis_wireless_isolation`，但当该字段缺失时，没有检查 `cgi_value` 的返回结果，而是直接将 `NULL` 作为参数传给 `nvram_set`，最终导致 `uhttpd` 进程崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。请求首先通过 `cgi_setobject` 读取 `submit_flag` 并命中 `wlan_g1_a1` 对应处理函数。随后在 `0x439058` 处调用 `cgi_value("wlg_guest_endis_wireless_isolation", ...)`。由于本样本请求体中缺少该字段，返回值为 `NULL`，并在 `0x439078` 被直接放入 `a1`。紧接着程序在 `0x43907c` 调用 `nvram_set("endis_wlg_guest_wireless_isolation", NULL)`，造成空指针解引用。

攻击者可以远程发起攻击，通过向 `/apply.cgi` 提交包含 `submit_flag=wlan_g1_a1`、但省略 `wlg_guest_endis_wireless_isolation` 字段的 POST 请求触发漏洞。本样本的原始请求正满足这一条件。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向 `/apply.cgi` 发送 POST 请求，请求体中设置 `submit_flag=wlan_g1_a1`，使程序进入 guest wireless 配置处理流程。虽然该请求包含其他参数和超长字段，但真正决定本次崩溃的数据项是缺失的 `wlg_guest_endis_wireless_isolation`。
![alt text](image-1.png)
![alt text](image-2.png)

第二步。程序在处理函数内调用 `cgi_value("wlg_guest_endis_wireless_isolation", ...)`，由于参数不存在，返回值为 `NULL`。该空指针随后直接作为第二个参数传给 `nvram_set`，在后续处理过程中被解引用，最终引发 `SIGSEGV` 并导致 `uhttpd` 进程崩溃。
![alt text](image.png)

相关问题代码：

0x43907c
