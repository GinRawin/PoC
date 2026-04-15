# 漏洞分析: xwn5001-0.4.1.1.zip / id:000139,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `unknown` `unknown`
- Source位置: `/usr/sbin/uhttpd` `unknown` `unknown`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 命令注入
- 一句话根因: `diag` 路径把 `body.pingName` 直接嵌进 `ping -c 3 %s > /tmp/ping_res` 的 shell 模板，并通过 `/bin/sh -c` 执行。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name -> /apply.cgi?upgrade_check_free.cgi` 定义原始请求 URL
  - `body.submit_flag(diag) + body.diag_type(1) -> 诊断分支选择`
  - `body.pingName -> ping 模板 "ping -c 3 %s > /tmp/ping_res" -> /bin/sh argv[2] -> /bin/ping argv[3]`
- 执行顺序:
  1. `POST /apply.cgi?upgrade_check_free.cgi` 进入 `diag` 诊断 CGI。
  2. 程序读取 `submit_flag=diag` 和 `diag_type=1`，进入 ping 诊断路径。
  3. `pingName` 被拼进 `ping -c 3 %s > /tmp/ping_res`。
  4. 入口进程 `19` 通过 `execve("/bin/sh",{"sh","-c",...})` 执行 shell 命令，并进一步 `execve("/bin/ping", ...)`。
  5. `ping` 对超长主机名报 `Unknown host`，随后父进程在 `0x32323232` 模式值附近崩溃。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- handler来源: `VulPacket.json -> packet_1.request.handler_name`
- body字段 `pingName`/`lookupName` 是参数值，不是原始 URL。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x4047d4`
- 命中的入口trace: `usr_sbin_uhttpd.txt`
- 子进程trace链: `10_tb_log.txt -> 19_tb_log.txt -> 22_tb_log.txt`
- 关键pc地址: `0x439e0c`, `0x439f20`, `0x32323232`

## 数据流细节

- 二进制字符串同时包含 `diag_type`、`pingName`、`lookupName` 和 `ping -c 3 %s > /tmp/ping_res`，说明该路径会以请求体字段驱动 shell 诊断命令。
- trace 703 直接显示 `/bin/sh -c "ping -c 3 <body.pingName> > /tmp/ping_res"`；`19_tb_log.txt` 又显示该命令继续展开为 `/bin/ping -c 3 <body.pingName>`。
- 容器日志里的 `ping: <超长主机名>: Unknown host` 与 trace 中的用户值完全一致，说明这是用户可控命令参数，而不是固定脚本噪声。

## 误报检查

- 这不是误报：用户字段、命令模板、shell 执行、控制台输出三者一致。
- 当前缺失的证据: 还没有精确恢复生成该命令模板的函数地址，因此 Source/Sink 地址保守记为 `unknown`。
- 替代解释: `Unknown host` 只是命令执行结果；真正的问题是用户值已经进入了 shell 模板。

## 证据

- `19_tb_log.txt:720` `pingName` 命中: `22 execve("/bin/ping",{"ping","-c","3","22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",NULL}) = 0`
- `usr_sbin_uhttpd.txt:703` `pingName` 命中: `19 execve("/bin/sh",{"sh","-c","ping -c 3 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 > /tmp/ping_res",NULL}) = 0`
- `usr_sbin_uhttpd.txt:707` `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`

- 关键容器日志行:
- `[qemu] Successful Bind 0`
- `[qemu] doing qemu_execven on filename /bin/sh`
- `[qemu] doing qemu_execven on filename /bin/ping`
- `ping: 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222: Unknown host`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`
- `[GreenHouseQEMU] SIG 11`

- 关键反编译证据:
  - 字符串同时存在 `pingName`、`diag_type`、`lookupName`、`ping -c 3 %s > /tmp/ping_res`、`/tmp/ping_res`。
