# 漏洞分析: tew-632brp-1.010b32.zip / id:000001,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd` `0x40c718` `0x40c82c`
- Source位置: `/sbin/httpd` `0x40c718` `0x40c7fc`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `内存破坏`
- 一句话根因: `ntp_sync.cgi*` 分支把 `body.ntp_server` 用 `sprintf` 写入位于 `sp+0x18` 的固定栈缓冲区，长度未校验，导致命令字符串覆盖返回现场并在函数尾部触发崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` + `request.prefix=/` + `request.handler_name=ntp_sync.cgi*` -> 原始请求 URL `/ntp_sync.cgi*` -> 进入 `/sbin/httpd` 的 `ntp_sync` 处理分支
  - `body.ntp_server` -> `get_cgi("ntp_server")` 返回值 `v0` -> `a2` at `0x40c818` -> `sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", v0)` at `0x40c82c`
  - `body.html_response_page` -> `get_cgi("html_response_page")` 返回值 `s0` -> 后续页面处理参数，不是本次崩溃的 source
  - `body.html_response_return_page` -> 未在已命中的易损写入链中被使用
- 执行顺序:
  1. `/ntp_sync.cgi*` 收到 POST 请求，`/sbin/httpd` 进入 `do_apply_post` 中的 `ntp_sync` 分支。
  2. `0x40c7fc` 调用 `get_cgi("ntp_server")` 读取 `body.ntp_server`。
  3. `0x40c82c` 用 `sprintf` 把 `ntp_server` 拼进栈上的命令缓冲区 `sp+0x18`。
  4. `0x40c860` 调用 `_system(sp+0x18)`，trace 记录到 `/bin/sh -c "ntpclient -h <body.ntp_server> -s -i 5 -c 1"`。
  5. 子进程 `/sbin/ntpclient` 报 `Unknown host` 退出后，父进程因栈返回状态被覆盖，在 `trace/sbin_httpd.txt` 中出现 `SIGSEGV`，`si_addr=0x202d6920` 对应命令文本中的 `" -i "`。

## 原始请求

- `VulPacket.json` 中的请求方法是 `POST`。
- 请求路径由 `request.prefix=/` 与 `request.handler_name=ntp_sync.cgi*` 组合得到，应按 `/ntp_sync.cgi*` 理解。
- 与漏洞链直接相关的字段是 `body.ntp_server=22222222222222222222222222222222`。
- `body.html_response_page` 参与响应页面路径处理，但不是本次越界写入的输入源。
- `body.html_response_return_page` 虽然很长，但在当前已命中的 trace/反汇编路径里没有进入危险写入点。

## Trace映射

- 父目录 `binary_summary.json` 给出的入口二进制是 `/sbin/httpd`，`main` 地址为 `0x40572c`。
- 当前 case 的 `trace_summary.json` 把 `14_tb_log.txt` 标记为入口 trace `trace/sbin_httpd.txt`。
- `trace/sbin_httpd.txt` 第 341-343 行显示：
  - `14 fork() = 17`
  - `17 execve("/bin/sh",{"sh","-c","ntpclient -h 22222222222222222222222222222222 -s -i 5 -c 1",NULL}) = 0`
- 同一文件第 363 行出现：
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x202d6920} ---`
- 子进程 `trace/17_tb_log.txt` 继续显示：
  - 第 573/576 行：`17 fork() = 20` / `17 fork() = 0`
  - 第 687 行：`20 execve("/sbin/ntpclient",{"ntpclient","-h","22222222222222222222222222222222","-s","-i","5","-c","1",NULL}) = 0`
  - 第 775 行：`17 exit(1)`
- `trace/20_tb_log.txt` 第 62 行是 `20 exit(1)`，与 `Unknown host` 日志一致。

## 关键地址与数据流

- `0x40c7ac` 先读取 `body.html_response_page`，把结果保存到 `s0`，这条链用于返回页面处理。
- `0x40c7fc` 读取真正进入危险写入点的字段 `body.ntp_server`，字符串字面量 `ntp_server` 位于 `0x437274`。
- `0x40c808` 把目标缓冲区设为 `sp+0x18`，随后 `0x40c82c` 调用 `sprintf`，格式串 `ntpclient -h %s -s -i 5 -c 1` 位于 `0x437280`。
- 该缓冲区仅在函数栈帧中临时分配，`sprintf` 没有长度限制；当前 32 字节 `ntp_server` 再加上固定前后缀后，生成的命令明显超过栈上预留空间。
- `0x40c838` 还会调用 `printf("ntp_sync_cgi: cmd=%s", sp+0x18)`，控制台中可见完整命令；`0x40c860` 随后把同一缓冲区传给 `_system`。
- `SIGSEGV` 的 `si_addr=0x202d6920` 与命令片段 `" -i "` 的 ASCII 字节一致，说明命令文本已经覆盖到返回控制数据。

## Console与行为证据

- `container.console.log` 记录：
  - `ntp_sync_cgi: cmd=ntpclient -h 22222222222222222222222222222222 -s -i 5 -c 1`
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /sbin/ntpclient`
  - `22222222222222222222222222222222: Unknown host`
  - `Segmentation fault (core dumped)`
- 这些日志与 trace 的 `/bin/sh` -> `/sbin/ntpclient` -> `SIGSEGV` 顺序完全一致。

## 判定理由

- source 明确：`get_cgi("ntp_server")` 在 `0x40c7fc` 读取 `body.ntp_server`。
- sink 明确：`sprintf(sp+0x18, "ntpclient -h %s -s -i 5 -c 1", ntp_server)` 在 `0x40c82c` 发生无界写入。
- `source -> variable -> sink` 闭环明确：`body.ntp_server -> get_cgi("ntp_server") -> a2 -> sprintf -> stack buffer sp+0x18 -> 栈返回状态被命令文本覆盖 -> SIGSEGV`。
- 虽然同一路径也存在 `_system(sp+0x18)` 的命令执行风险，但本样本的直接失效现象是 `sprintf` 触发的栈破坏，因此本 case 的主判定应为 `内存破坏`，不是误报。
