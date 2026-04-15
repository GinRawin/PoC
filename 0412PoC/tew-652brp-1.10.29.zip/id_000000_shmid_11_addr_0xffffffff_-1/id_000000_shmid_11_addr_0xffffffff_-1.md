# 漏洞分析: tew-652brp-1.10.29.zip / id:000000,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x40a4bc 0x40c860`
- Source位置: `/sbin/httpd 0x40a4bc 0x40c7fc`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `ntp_sync.cgi*` 处理路径把 `body.ntp_server` 直接格式化进 `ntpclient -h %s -s -i 5 -c 1`，随后通过 `_system` 交给 `/bin/sh -c` 执行，没有做任何转义或白名单校验。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=ntp_sync.cgi*` -> 命中 `/ntp_sync.cgi*` 对应的 NTP 同步处理路径
  - `body.ntp_server` -> `get_cgi("ntp_server")` 返回值 `v0` -> `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", v0)` 的 `%s` 参数 -> `_system(sp+0x18)`
  - `body.html_response_page` -> `get_cgi("html_response_page")` 返回值 `s0` -> `_system` 返回后传给 `absolute_path(s0)` 用于响应页面跳转
- 执行顺序:
  1. `POST /ntp_sync.cgi*` 到达 `httpd_main`，入口 trace 命中 `trace/sbin_httpd.txt`。
  2. `do_apply_post` 在 `0x40c7fc` 调 `get_cgi("ntp_server")` 读取 `body.ntp_server`。
  3. `do_apply_post` 在 `0x40c82c` 用格式串 `ntpclient -h %s -s -i 5 -c 1` 组装栈上命令缓冲区，并在 `0x40c848` 打印 `ntp_sync_cgi: cmd=%s`。
  4. `do_apply_post` 在 `0x40c860` 调 `_system`，trace 显示父进程 `fork()` 后子进程 `execve("/bin/sh",{"sh","-c","ntpclient -h 222... -s -i 5 -c 1",...})`。
  5. shell 再 `fork/execve("/sbin/ntpclient",{"ntpclient","-h","222...",...})`，控制台出现 `Unknown host`；随后父进程继续响应处理并最终触发 `SIGSEGV`，但命令执行链在崩溃前已经成立。

## 原始请求

- `VulPacket.json` 中只有 1 个请求包。
- 原始请求方法来自 `packet_1.request.method`: `POST`
- 原始 URL/handler 来自 `packet_1.request.prefix` 与 `packet_1.request.handler_name`: `/ntp_sync.cgi*`
- `body` 中的 `ntp_server`、`html_response_page`、`html_response_return_page`、`reboot_type`、`revoke_mac`、`revoke_ip` 都是请求体参数，不是原始 URL。

## Trace映射

- 入口二进制: `/sbin/httpd`
- `main` 地址: `0x40572c`
- 自动匹配 trace: `trace/sbin_httpd.txt`
- 关键 trace 链:
  - `trace/sbin_httpd.txt:325-344` 命中 `0x40c718 -> 0x40c860` 这段 `do_apply_post` 路径
  - `trace/sbin_httpd.txt:341` `14 fork() = 17`
  - `trace/sbin_httpd.txt:343` `17 execve("/bin/sh",{"sh","-c","ntpclient -h 222... -s -i 5 -c 1",NULL}) = 0`
  - `trace/17_tb_log.txt:589` `17 fork() = 20`
  - `trace/17_tb_log.txt:688` `20 execve("/sbin/ntpclient",{"ntpclient","-h","222...",...}) = 0`
  - `trace/sbin_httpd.txt:363` `--- SIGSEGV ... si_addr=0x32323232 ---`
- 子进程链: `httpd(pid 14) -> /bin/sh(pid 17) -> /sbin/ntpclient(pid 20)`

## 关键数据流

- `0x40c7b0-0x40c7d0`: `do_apply_post` 先读取 `html_response_page`
- `0x40c7e0-0x40c7fc`: 同一函数再次调用 `get_cgi("ntp_server")`
- `0x40c808-0x40c82c`: `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ntp_server)`
- `0x40c838-0x40c84c`: 用 `ntp_sync_cgi: cmd=%s` 打印最终命令
- `0x40c858-0x40c860`: `_system(sp+0x18)`，这是实际危险 sink

`container.console.log` 与反汇编完全对齐:

```text
ntp_sync_cgi: cmd=ntpclient -h 222... -s -i 5 -c 1
[qemu] doing qemu_execven on filename /bin/sh
[qemu] doing qemu_execven on filename /sbin/ntpclient
222...: Unknown host
```

这说明即使当前样本没有放入分号、反引号或 `$()` 之类元字符，用户输入也已经未经约束地进入 shell 命令模板并被执行，命令注入漏洞已成立。

## 崩溃与漏洞关系

- `SIGSEGV` 发生在命令执行之后，不是确认命令注入所必需的唯一证据。
- 当前更稳妥的结论是:
  - 真正可闭环确认的漏洞是 `ntp_server -> sprintf -> _system("/bin/sh -c ...")` 的命令注入。
  - 后续 `SIGSEGV si_addr=0x32323232` 更像是响应处理阶段又消费了用户可控数据导致的附加异常，但仅靠现有 trace 还不足以把这个崩溃单独恢复成另一条完整的 `source -> sink` 内存破坏链。

## 误报检查

- 不是误报的原因:
  - source 可解释: `get_cgi("ntp_server")` at `0x40c7fc`
  - sink 可解释: `_system` at `0x40c860`
  - 数据流可解释: `body.ntp_server -> 栈命令缓冲区 -> /bin/sh -c`
  - trace / console / 反汇编三者一致
- 当前未完全恢复的部分:
  - `SIGSEGV` 的精确崩溃函数和地址链未完全恢复
- 但这不会影响当前 case 作为确认命令注入漏洞的结论，因为危险 sink 在崩溃前已经被实际触发。

## 证据

- 关键反汇编证据:
  - `0x40c7fc`: `get_cgi("ntp_server")`
  - `0x40c82c`: `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ...)`
  - `0x40c848`: 打印 `ntp_sync_cgi: cmd=%s`
  - `0x40c860`: `_system(sp+0x18)`
- 关键 trace 证据:
  - `trace/sbin_httpd.txt:343` `/bin/sh -c "ntpclient -h 222... -s -i 5 -c 1"`
  - `trace/17_tb_log.txt:688` `/sbin/ntpclient -h 222...`
- 关键控制台证据:
  - `ntp_sync_cgi: cmd=ntpclient -h 222... -s -i 5 -c 1`
  - `222...: Unknown host`
  - `SIGSEGV`

## 命中benchmark:否

## 0-day:是