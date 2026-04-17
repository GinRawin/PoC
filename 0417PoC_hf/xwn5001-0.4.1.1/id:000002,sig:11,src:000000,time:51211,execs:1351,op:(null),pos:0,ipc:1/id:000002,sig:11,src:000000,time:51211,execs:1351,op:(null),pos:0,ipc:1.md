http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 0x40f824 路径格式化栈缓冲区溢出漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的超长 GET 请求路径触发该问题。程序在 `handle_request` 中将请求目标直接传入回调函数 `0x40f824`，后者在栈缓冲区中通过 `sprintf` 格式化该字符串，未做长度校验，导致保存的返回地址被覆盖并使 `uhttpd` 崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。请求路径在 `handle_request` 的 `0x409c80` 处被作为参数传入 `fcn.0040f824`。该函数在 `0x40fae0` 调用 `sprintf`，目标缓冲区位于 `sp+0x18`，而保存的 `ra` 位于 `sp+0x4ac`。样本中的路径长度远超该栈帧可承受范围，最终在函数尾声 `0x40fd14` 附近恢复返回地址时触发崩溃。

攻击者可以远程发起攻击，通过构造超长 URI 路径触发漏洞。本样本中的原始请求以 `GET /.htm... HTTP/1.1` 开始，路径中包含大段重复的可控字符，是导致栈覆盖的直接输入。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向设备发送超长 GET 请求，请求目标以 `/.htm` 开头，并附加大量攻击者可控数据。`uhttpd` 在处理该请求时，将请求目标保存到寄存器变量中，并在后续分派逻辑里直接作为参数传给回调函数 `0x40f824`。
![alt text](image-1.png)
![alt text](image-2.png)

第二步。回调函数在 `0x40fae0` 处调用 `sprintf`，将可控路径写入栈上的本地缓冲区。由于输入长度明显大于从 `sp+0x18` 到 `sp+0x4ac` 的空间范围，保存的 `ra` 被覆盖，函数返回阶段跳转到 `0x61616160` 并触发 `SIGSEGV`。这表明崩溃地址已经被请求中的 `'a'` 字节污染。
![alt text](image.png)

相关问题代码：

0x40fae0
