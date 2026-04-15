# 漏洞分析: tew-673gru-1.00b40.zip / id:000001,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x40d980 0x40da44`
- Source位置: `/sbin/httpd 0x40d980 0x40da14`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `内存破坏`
- 一句话根因: `ntp_sync.cgi*` 处理逻辑把 `body.ntp_server` 直接带入 `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ntp_server)`，在仅 0x50 字节栈帧内造成大范围覆盖，最终把返回地址附近打成 `0x32323232`。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/" + request.handler_name="ntp_sync.cgi*"` -> `parse_http_url_request()` 选择 NTP 同步 handler
  - `body.ntp_server` -> `get_cgi("ntp_server") @ 0x40da14` -> `v0/a2` -> `sprintf` 第 3 个参数 -> 栈缓冲区 `sp+0x18`
  - `body.html_response_page="1"` -> 前置 `get_cgi("html_response_page") @ 0x40d9e8` -> `s0` -> `absolute_path(s0) @ 0x40da90` -> 重定向页面
  - `body.test` / `body.lan_device_name` / `body.wps_pin` / `body.admin_password` / `body.reboot_type` / `body.html_response_return_page` -> 在当前命中的溢出路径里未观察到进入危险 sink
- 执行顺序:
  1. `POST /ntp_sync.cgi*` 命中 NTP 同步 CGI，请求 URL 来自 `request`，不是 body 中看起来像命令的数据值。
  2. handler 先读取 `html_response_page`，随后在 `0x40da14` 读取 `ntp_server`。
  3. `0x40da44` 使用固定模板 `ntpclient -h %s -s -i 5 -c 1` 将超长 `ntp_server` 无界写入 `sp+0x18`。
  4. 同一被破坏缓冲区被用于 `_system(cmd) @ 0x40da78`，于是派生 `/bin/sh -c ...` 和 `/sbin/ntpclient -h <超长字符串> ...`。
  5. 命令返回后 handler 继续执行，因保存寄存器/返回地址已被 `'2'` 覆盖，trace 在 `0x40dae4` 后出现 `SIGSEGV si_addr=0x32323232`。

## Trace映射

- 入口二进制: `/sbin/httpd`
- Main地址: `0x405d6c`
- 命中的入口trace: `trace/sbin_httpd.txt`
- 子进程trace链:
  - `trace/12_tb_log.txt`: `12 fork() = 14`，`14 execve("/sbin/httpd",{"/sbin/httpd",NULL}) = 0`
  - `trace/sbin_httpd.txt`: `14 fork() = 17`，`17 execve("/bin/sh",{"sh","-c","ntpclient -h <超长ntp_server> -s -i 5 -c 1",NULL}) = 0`
  - `trace/17_tb_log.txt`: `17 fork() = 20`，`20 execve("/sbin/ntpclient",{"ntpclient","-h","<超长ntp_server>","-s","-i","5","-c","1",NULL}) = 0`
  - `trace/20_tb_log.txt`: `20 exit(1)`
  - `trace/17_tb_log.txt`: `17 exit(1)`
  - `trace/sbin_httpd.txt`: `SIGSEGV si_addr=0x32323232`
- 关键pc地址:
  - `0x40da14`: `get_cgi("ntp_server")`
  - `0x40da44`: `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ntp_server)`
  - `0x40da78`: `_system(sp+0x18)`
  - `0x40da90`: `absolute_path(s0)`
  - `0x40dae4`: 返回前触发崩溃的位置附近
  - `0x4047e0`: `/sbin/ntpclient main`

## 数据流细节

- 原始请求方法、URL、handler:
  - 方法来自 `packet_1.request.method`: `POST`
  - 路径来自 `packet_1.request.prefix="/"` 与 `packet_1.request.handler_name="ntp_sync.cgi*"`
  - `body.ntp_server` 只是请求体参数，不是原始 URL
- 关键反汇编:
  - `0x40d9f8` 载入 `get_cgi`，`0x40da04` 形成字符串地址 `0x43b098 ("ntp_server")`，`0x40da14` 调用 `get_cgi("ntp_server")`
  - `0x40da20` 把目标缓冲区设为 `sp+0x18`
  - `0x40da2c` 形成格式串地址 `0x43b0a4 ("ntpclient -h %s -s -i 5 -c 1")`
  - `0x40da44` 调用 `sprintf(sp+0x18, fmt, ntp_server)`，没有长度检查
  - `0x40da78` 将同一缓冲区传给 `_system`
- 为什么这是内存破坏而不是单纯命令执行:
  - console 明确打印了拼接后的超长命令：`ntp_sync_cgi: cmd=ntpclient -h 2222... -s -i 5 -c 1`
  - `trace/sbin_httpd.txt` 在 `_system` 路径之后出现 `SIGSEGV si_addr=0x32323232`
  - `0x32323232` 恰好对应 ASCII `'2222'`，说明栈上控制数据被输入中的 `'2'` 覆盖
  - 该 handler 栈帧只保留到 `sp+0x48` 的保存寄存器/返回地址，而 `ntp_server` 长度远超 `sp+0x18` 可用空间，溢出解释与 trace/console 一致
- 子进程行为:
  - `/sbin/ntpclient` 接收到超长 `-h` 参数后打印 `Unknown host` 并 `exit(1)`
  - 真正的崩溃发生在父 `httpd` handler 返回阶段，不需要依赖 `ntpclient` 自身崩溃才能成立

## 误报检查

- 为什么这是确认漏洞:
  - source 明确：`body.ntp_server -> get_cgi("ntp_server")`
  - sink 明确：`sprintf(sp+0x18, fmt, ntp_server)`，且 fmt 为固定字符串、无长度限制
  - 数据流明确：`ntp_server -> v0/a2 -> sprintf arg#3 -> stack buffer sp+0x18 -> _system(cmd) -> 覆盖返回地址`
  - 证据闭环明确：反汇编、trace、console 三者一致，且 `SIGSEGV si_addr=0x32323232` 与输入字符一致
- 当前缺失的证据:
  - 没有必要再依赖更深的 `ntpclient` 反编译；`httpd` 内的栈溢出已经足以解释现象
- 对当前现象的替代解释:
  - `Unknown host` 只是 `ntpclient` 对超长主机名的运行结果，不足以单独解释后续 `httpd` 的 `0x32323232` 崩溃
  - 若没有 `sprintf` 溢出，就无法合理解释父进程在命令返回后崩到攻击者控制地址

## 证据

- 关键trace行:
  - `trace/sbin_httpd.txt:362`: `17 execve("/bin/sh",{"sh","-c","ntpclient -h 2222... -s -i 5 -c 1",NULL}) = 0`
  - `trace/sbin_httpd.txt:382`: `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`
  - `trace/17_tb_log.txt:675`: `20 execve("/sbin/ntpclient",{"ntpclient","-h","2222...","-s","-i","5","-c","1",NULL}) = 0`
  - `trace/20_tb_log.txt:62`: `20 exit(1)`
  - `trace/17_tb_log.txt:763`: `17 exit(1)`
  - `trace/12_tb_log.txt:863`: `12 exit(139)`
- 关键容器日志行:
  - `ntp_sync_cgi: cmd=ntpclient -h 2222... -s -i 5 -c 1`
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /sbin/ntpclient`
  - `2222...: Unknown host`
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
- 关键反编译证据:
  - `0x43b098`: `"ntp_server"`
  - `0x43b0a4`: `"ntpclient -h %s -s -i 5 -c 1"`
  - `0x40da14`: `get_cgi("ntp_server")`
  - `0x40da44`: `sprintf(sp+0x18, fmt, ntp_server)`
  - `0x40da78`: `_system(sp+0x18)`
