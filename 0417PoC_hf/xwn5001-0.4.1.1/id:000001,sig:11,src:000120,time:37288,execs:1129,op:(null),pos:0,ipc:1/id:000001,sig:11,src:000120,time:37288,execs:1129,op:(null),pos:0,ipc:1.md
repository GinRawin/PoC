http://www.downloads.netgear.com/files/GDC/XWN5001/XWN5001-V0.4.1.1.zip

漏洞名称：
Netgear XWN5001 0.4.1.1 静态文件路径处理栈缓冲区溢出漏洞

Netgear XWN5001 0.4.1.1 是 Netgear 公司旗下的一款网络设备固件，受影响产品为 XWN5001，受影响版本为 0.4.1.1。

Netgear XWN5001 0.4.1.1 的 `/usr/sbin/uhttpd` 二进制文件中存在一个栈缓冲区溢出漏洞。远程攻击者可以通过发送构造的超长静态资源访问路径触发该漏洞。程序在处理该请求时，会将 URL 路径直接传入文件访问逻辑，并使用 `sprintf` 分别拼接 `/tmp/%s` 和 `/www/%s` 到栈上的局部缓冲区中，没有对输入长度做限制，最终覆盖返回地址并导致 `uhttpd` 进程崩溃。

该漏洞位于二进制文件 `/usr/sbin/uhttpd` 中。请求分发逻辑会在 `0x409c80` 处将请求路径作为首参数传入目标处理函数。目标函数在 `0x405a20` 和 `0x405a58` 先后执行 `sprintf(sp+0x18, "/tmp/%s", a0)` 与 `sprintf(sp+0x18, "/www/%s", a0)`。由于目标缓冲区位于栈上且长度固定，超长路径会覆盖保存的 `ra`，在函数尾声 `0x405bac` 附近跳转到异常地址 `0x61616160`。

攻击者可以远程发起攻击，通过构造包含超长文件名的 GET 请求触发漏洞。本样本中的请求以 `GET /cc.js... HTTP/1.1` 开始，路径后跟随大量可控字符，能够稳定进入该危险分支。

漏洞研究环境：

通过模拟仿真进行验证。当前附件中的环境是已经 patch 了认证环节之后的，未 patch 的环境可以通过上述下载链接获取对应固件。

通过 greenhouse 进行仿真，greenhouse 链接为 https://github.com/sefcom/greenhouse。仿真环境搭建的具体命令链接为 https://github.com/sefcom/greenhouse/blob/master/MANUAL.md。
我在附件里面附上了 rehost 的镜像，链接为 https://github.com/GinRawin/PoC/blob/main/0412PoC/xwn5001-0.4.1.1.zip/xwn5001-0.4.1.1.tar.gz，启动的命令为进入到 dockerfile 目录下，然后 `docker-compose build`, `docker-compose up`。

目标配置情况：

没有进行特殊配置，默认仿真环境启动。

具体验证过程：

第一步。攻击者向目标设备发送访问静态资源的 GET 请求，请求路径以 `/cc.js` 为前缀，并附加超长的可控字符串。`uhttpd` 在请求分发阶段识别该路径后，将对应的 path 指针直接传入静态文件定位函数，用于后续构造文件系统路径。
![alt text](image-1.png)
![alt text](image-2.png)

第二步。程序在目标函数内部先尝试拼接 `/tmp/%s`，若未命中再继续拼接 `/www/%s`。由于两次 `sprintf` 都把攻击者可控路径写入同一个栈缓冲区 `sp+0x18`，而没有任何边界检查，超长字符串最终覆盖保存的返回地址。函数返回时 `ra` 已被污染为 `0x61616160`，导致 `uhttpd` 进程崩溃。
![alt text](image.png)

相关问题代码：

0x405a20
0x405a58
