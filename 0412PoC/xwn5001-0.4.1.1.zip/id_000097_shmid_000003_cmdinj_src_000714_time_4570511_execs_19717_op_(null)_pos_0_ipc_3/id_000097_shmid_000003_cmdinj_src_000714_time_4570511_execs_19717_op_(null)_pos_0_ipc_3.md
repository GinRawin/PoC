# 漏洞分析: xwn5001-0.4.1.1.zip / id:000097,shmid:000003,cmdinj,src:000714,time:4570511,execs:19717,op:(null),pos:0,ipc:3

## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `0x40cb78` `0x40cc34`
- Source位置: `/usr/sbin/uhttpd` `0x40cb78` `0x40cbf8`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 命令注入
- 一句话根因: `hijack_dhcp` 路径把 `body.pppoe_ipaddr` 直接格式化进 `/sbin/ipconflict %s %s noexec`，随后交给 `system()` 走 `/bin/sh -c`。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name -> /apply.cgi?hijack_dhcp` 定义原始请求 URL
  - `body.submit_flag(hijack_pppoe) -> CGI 分支选择 -> hijack/wan 提交路径`
  - `body.pppoe_ipaddr -> sym.cgi_value @ 0x40cbf8 返回值 -> [sp+0x10] -> snprintf arg#4 @ 0x40cc24 -> 栈缓冲区 [sp+0x20] -> system @ 0x40cc34`
  - `body.pppoe_ipaddr -> trace 741 / 19_tb_log 588 中的 `/sbin/ipconflict <user> 255.255.255.255 noexec``
- 执行顺序:
  1. `POST /apply.cgi?hijack_dhcp` 进入 `/usr/sbin/uhttpd` 的 CGI 提交路径。
  2. `submit_flag=hijack_pppoe` 使请求走到 `hijack` WAN 处理逻辑。
  3. `sym.detect_ipconflict` 在 `0x40cbf8` 通过 `cgi_value` 读取 `pppoe_ipaddr`。
  4. `sym.detect_ipconflict` 在 `0x40cc24`/`0x40cc34` 先 `snprintf` 再 `system` 触发 shell。
  5. 子进程 `19`/`22` 执行 `/sbin/ipconflict <user> 255.255.255.255 noexec`，因为目标程序缺失而 `exit(127)`；随后父路径继续固定执行 `/etc/init.d/net-wan restart`。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?hijack_dhcp`
- handler来源: `VulPacket.json -> packet_1.request.handler_name`
- body字段只作为参数值参与后续数据流，不定义原始 URL。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x4047d4`
- 命中的入口trace: `usr_sbin_uhttpd.txt`
- 子进程trace链: `10_tb_log.txt -> 19_tb_log.txt -> 26_tb_log.txt`
- 关键pc地址: `0x40cb78`, `0x40cbf8`, `0x40cc24`, `0x40cc34`

## 数据流细节

- `sym.detect_ipconflict` 的反编译显示：`cgi_value(...)` 先取请求字段，再用 `"/sbin/ipconflict %s %s noexec"` 组命令，然后 `system()` 执行。
- trace 直接证明 `body.pppoe_ipaddr` 的长字符串出现在 `execve("/bin/sh",{"sh","-c","/sbin/ipconflict ..."})` 中，随后又在 `19_tb_log.txt` 里展开为 `execve("/sbin/ipconflict", ...)`。
- 同一路径下的 `/etc/init.d/net-wan restart` 是固定后续动作，不影响前面的用户可控 shell sink 已经成立。

## 误报检查

- 这不是误报：source、命令模板、shell sink、子进程执行链都能对齐。
- 当前缺失的证据: 无法精确恢复更上游的 handler 函数名，但不影响 `source -> variable -> sink` 闭环。
- 替代解释: `/sbin/ipconflict` 缺失只解释了为什么子进程 `exit(127)`，不能解释用户值为何已进入 `system()` 命令模板。

## 证据

- `19_tb_log.txt:588` `pppoe_ipaddr` 命中: `22 execve("/sbin/ipconflict",{"/sbin/ipconflict","222222222222222222222222222222222222222222222222222222222wzq22222222222222222222222222222222222222222222222222222222222222222222","255.255.255.255","noexec",NULL}) = 0`
- `usr_sbin_uhttpd.txt:741` `pppoe_ipaddr` 命中: `19 execve("/bin/sh",{"sh","-c","/sbin/ipconflict 222222222222222222222222222222222222222222222222222222222wzq22222222222222222222222222222222222222222222222222222222222222222222 255.255.255.255 noexec",NULL}) = 0`
- `usr_sbin_uhttpd.txt:839` `--- SIGCHLD {si_signo=SIGCHLD, si_code=1, si_pid=19, si_uid=0, si_status=127, si_utime=4, si_stime=6} ---`
- `usr_sbin_uhttpd.txt:938` `--- SIGCHLD {si_signo=SIGCHLD, si_code=1, si_pid=24, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---`

- 关键容器日志行:
- `[qemu] doing qemu_execven on filename /bin/sh`
- `[qemu] doing qemu_execven on filename /sbin/ipconflict`
- `sh: /sbin/ipconflict: not found`
- `[qemu] doing qemu_execven on filename /bin/sh`
- `[qemu] doing qemu_execven on filename /etc/init.d/net-wan`
- `sh: /etc/init.d/net-wan: not found`

- 关键反编译证据:
  - `sym.detect_ipconflict @ 0x40cb78`: `cgi_value` 读取字段后，在 `0x40cc24` 使用 `"/sbin/ipconflict %s %s noexec"` 调 `snprintf`，在 `0x40cc34` 调 `system`。
  - `sym.cmd_hijack_wan @ 0x431b54`: 固定执行 `"/etc/init.d/net-wan restart"`。
