# 漏洞分析: tew-634gru-1.01b14.zip / id:000001,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x40a654 0x40c9f8`
- Source位置: `/sbin/httpd 0x40a654 0x40c994`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `do_apply_post` 从 `body.ntp_server` 读取用户输入后，在栈上用 `sprintf("ntpclient -h %s -s -i 5 -c 1", ntp_server)` 组装 shell 命令，并通过 `_system()` 交给 `/bin/sh -c` 执行，输入未做 shell 级过滤。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/" + request.handler_name="ntp_sync.cgi*"` -> 选择 NTP 同步处理分支
  - `body.ntp_server` -> `get_cgi("ntp_server")` 返回值 `s0` -> `sprintf` 的 `%s` 参数 `a2` -> 栈上命令缓冲区 `sp+0x18`
  - `body.ntp_server` -> `/bin/sh -c "ntpclient -h <ntp_server> -s -i 5 -c 1"` -> `/sbin/ntpclient -h <ntp_server>`
  - `body.html_response_page` / `body.html_response_return_page` / `body.revoke_ip` / `body.revoke_mac` / `body.test` -> 本次已确认路径中未观察到进入命令模板
- 执行顺序:
  1. `POST /ntp_sync.cgi*` 命中 NTP 同步处理逻辑。
  2. `do_apply_post` 在 `0x40c994` 调用 `get_cgi("ntp_server")` 取出 `body.ntp_server`。
  3. `do_apply_post` 在 `0x40c9c4` 调用 `sprintf`，用模板 `ntpclient -h %s -s -i 5 -c 1` 生成命令字符串。
  4. `do_apply_post` 在 `0x40c9f8` 调用 `_system()`，随后 `httpd` fork 并 `execve("/bin/sh", {"sh","-c","ntpclient -h 2222... -s -i 5 -c 1"})`。
  5. shell 再派生 `/sbin/ntpclient -h 2222...`；`Unknown host` 和后续 `SIGSEGV` 是命令执行后的次生现象，不影响命令注入链条成立。

## 原始请求

- 方法: `POST`
- URL: `/ntp_sync.cgi*`
- handler: `ntp_sync.cgi*`
- URL 来源: `VulPacket.json` 中 `packet_1.request.prefix="/"` 与 `packet_1.request.handler_name="ntp_sync.cgi*"`
- body 参数:
  - `test`
  - `html_response_return_page`
  - `revoke_ip`
  - `revoke_mac`
  - `html_response_page`
  - `ntp_server`

这里要区分:

- 原始请求 URL 是 `/ntp_sync.cgi*`
- `ntp_server` 是 body 参数值，不是 URL；它在后续数据流里被拿来填入 shell 命令模板

## Trace映射

- 入口二进制: `/sbin/httpd`
- `main` 地址: `0x40582c`
- 命中的入口 trace: `trace/sbin_httpd.txt`
  - `trace_summary.json` 已自动匹配 `main_addr=0x40582c`
  - 匹配策略: `exact_main`
- 子进程链:
  - `httpd(pid 14)` -> `fork()` -> `sh(pid 17)` -> `fork()` -> `ntpclient(pid 20)`
- 关键 trace:
  - `trace/sbin_httpd.txt:341-344`
    - `pc=0x436b00`
    - `14 fork() = 17`
    - `14 fork() = 0`
    - `17 execve("/bin/sh",{"sh","-c","ntpclient -h 22222222222222222222222222222222 -s -i 5 -c 1",NULL}) = 0`
  - `trace/17_tb_log.txt:573-687`
    - `17 fork() = 20`
    - `20 execve("/sbin/ntpclient",{"ntpclient","-h","22222222222222222222222222222222","-s","-i","5","-c","1",NULL}) = 0`
  - `trace/sbin_httpd.txt:365`
    - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x202d6920} ---`
  - `trace/20_tb_log.txt:62`
    - `20 exit(1)`

## 关键数据流

`do_apply_post` 中的关键片段位于 `0x40c978-0x40c9fc`:

- `0x40c978-0x40c994`
  - 调用 `get_cgi("ntp_server")`
  - 返回值保存在 `s0`
- `0x40c9a0-0x40c9c4`
  - `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", s0)`
- `0x40c9d0-0x40c9e4`
  - 使用 `ntp_sync_cgi: cmd=%s` 打印拼接后的命令
- `0x40c9f0-0x40c9fc`
  - `_system(sp+0x18)`

因此数据流可以明确写成:

- `body.ntp_server`
  -> `get_cgi("ntp_server")`
  -> `s0`
  -> `sprintf` arg#3 (`%s`)
  -> 栈缓冲区 `sp+0x18`
  -> `_system(sp+0x18)`
  -> `/bin/sh -c`
  -> `/sbin/ntpclient -h <user_input>`

## Console与反编译证据

- `container.console.log`
  - `ntp_sync_cgi: cmd=ntpclient -h 22222222222222222222222222222222 -s -i 5 -c 1`
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /sbin/ntpclient`
  - `22222222222222222222222222222222: Unknown host`
- 二进制字符串
  - `ntp_server`
  - `ntpclient -h %s -s -i 5 -c 1`
  - `ntp_sync_cgi: cmd=%s`
- 关键反汇编
  - `0x40c980 addiu a0, ..., "ntp_server"`
  - `0x40c994 jalr t9` -> `get_cgi`
  - `0x40c9a8 addiu a1, ..., "ntpclient -h %s -s -i 5 -c 1"`
  - `0x40c9c4 jalr t9` -> `sprintf`
  - `0x40c9e0 jalr t9` -> 日志打印 `ntp_sync_cgi: cmd=%s`
  - `0x40c9f0 lw t9, -sym.imp._system(gp)`
  - `0x40c9f8 jalr t9` -> `_system`

## 为什么这是确认漏洞

- 已有可解释 source:
  - `get_cgi("ntp_server")` 在 `0x40c994`
- 已有可解释 sink:
  - `_system()` 在 `0x40c9f8`
- 已有完整 `source -> variable -> sink` 闭环:
  - `body.ntp_server -> s0 -> sprintf("%s") -> sp+0x18 -> _system -> /bin/sh -c`
- trace / console / 反编译三者一致:
  - console 打印了完整拼接命令
  - trace 显示 `/bin/sh -c` 执行该命令
  - 进一步 trace 到 `/sbin/ntpclient -h <user_input>`

后续的 `Unknown host`、`exit(1)` 与 `SIGSEGV` 只是当前 payload 和模拟环境下的运行结果；命令注入危险行为在 shell 启动时就已经成立，不需要依赖这些次生现象来证明。
