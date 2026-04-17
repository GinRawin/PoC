# 漏洞分析: wndrmacv1-1.0.0.20 / id:000002,sig:11,src:000000,time:24944,execs:891,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_file 0x4089cc (jalr -> sprintf@0x445790, 目标缓冲区为 sp+0x18)`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x40b048-0x40b07c (从请求行解析第二个 token，并保存在 sp+0x2730)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `栈缓冲区溢出`
- 一句话根因: `handle_request` 将请求 URI 直接传给 `do_file`，后者用 `sprintf("/www/%s", uri)` 把用户可控长路径写入仅 0x88 字节左右的栈缓冲区，覆盖保存的寄存器和返回地址，最终在函数返回时触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `request.prefix` + `request.handler_name` -> `handle_request` 中请求行第二个 token 指针 `sp+0x2730` / `s3`
  - `request.handler_name` -> `do_file` 中 `sprintf` 的 `a2`
- 执行顺序:
  1. `handle_request` 用 `fgets` 读取 HTTP 请求行到栈上，再用 `strsep` 按空格切分，请求 URI 起始指针保存在 `sp+0x2730`。
  2. `handle_request` 在静态文件分支中用 `s3=*(sp+0x2730)` 参与 `mime_handlers` 匹配，并在 `0x40c3f8` 把该指针作为 `a0` 调用 `do_file`。
  3. `do_file` 在 `0x4089cc` 调用 `sprintf(sp+0x18, "/www/%s", a0)`，长 URI 覆盖到 `ra` 保存槽；函数结束于 `0x408a94` 取回损坏栈帧时崩溃。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x407940`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `entry_trace` 显示 `uhttpd` 先后 `fork()`；崩溃 pc 序列继续落在同一二进制地址空间内，未看到额外子进程 trace 文件承载该崩溃链
- 关键pc地址:
  - `0x40c3ec -> 0x40c3f8`: `handle_request` 取出 handler 表项函数指针并以 `a0=s3` 调用
  - `0x408998`: 进入 `sym.do_file`
  - `0x4089cc`: 调用 `sprintf`
  - `0x408a94`: 函数尾 `lw ra, 0xa0(sp)`，此处因栈损坏崩溃
  - `si_addr=0x61616160`: 异常地址呈现为攻击者填充的 `'a'`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.method = GET` 使请求走静态文件读取逻辑，而不是 CGI/POST 路径。
  - `request.prefix = "/"` 与 `request.handler_name` 共同组成请求 URI `/cc.gifaaaa...`，其第二个请求行 token 被 `handle_request` 保存在 `sp+0x2730`。
  - `request.handler_name` 以 `cc.gif` 开头，满足静态资源后缀匹配条件，命中 `mime_handlers` 中 `.gif` 类表项并选择 `do_file`。
  - `body.wan_dhcp_ipaddr` 未参与该崩溃路径。
- 哪个函数读取了source字段:
  - `sym.handle_request` 在 `0x40b010` 用 `fgets` 把整行请求读入 `sp+0x20`，随后在 `0x40b048` / `0x40b098` / `0x40b0f4` 连续 `strsep` 按空格拆分；其中 `sp+0x2730` 保留了 URI token 的起始地址，后续在 `0x40c3b8` 重新装入 `s3`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_file` 在 `0x4089c4` 准备 `a2=a0`，`0x4089c8` 准备格式串 `"/www/%s"`，`0x4089d0` 指定目标缓冲区 `sp+0x18`，并在 `0x4089cc` 经 `jalr` 调用 `sprintf`。
- 最终如何到达sink:
  - `VulPacket.json` 中的超长 `request.handler_name`
  - `->` HTTP 请求行中的 URI `/cc.gifaaaa...`
  - `->` `handle_request` 解析后保存的 URI 指针 `sp+0x2730`
  - `->` `0x40c3f8` 作为 `a0` 传给 `do_file`
  - `->` `do_file` 中 `a2`
  - `->` `sprintf(sp+0x18, "/www/%s", a2)`
  - `->` 覆盖 `ra` 保存槽 `sp+0xa0`
  - `->` `0x408a94` 取回损坏返回地址时触发 `SIGSEGV`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃不是偶发模拟误差。容器日志明确记录 `SIGSEGV`，入口 trace 最后一条为 `--- SIGSEGV ... si_addr=0x61616160 ---`，异常地址与请求中的 `'a'` 填充一致。
  - 反汇编显示真正危险点不是函数尾，而是 `do_file` 中无界 `sprintf`；崩溃点 `0x408a94` 只是栈被覆盖后的显性故障点。
  - 数据流可闭合到具体包字段: 请求 URI 来自 `request.prefix` + `request.handler_name`，并被原样传给 `sprintf` 的 `%s` 参数。
- 当前缺失的证据:
  - 没有寄存器快照或内存转储来直接展示 `ra` 被写成哪一段精确字节序。
  - 但这不影响漏洞判定，因为 sink、溢出方向和 fault site 已由反汇编与 trace 共同闭合。
- 对当前现象的替代解释:
  - 最合理替代解释是空指针或文件打开失败后异常返回；但 `do_file` 中 `fopen` 失败分支只会直接走函数尾，不会制造 `0x61616160` 这种攻击者模式地址，因此不成立。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x40c3ec -> 0x40c3f8 -> 0x408998 -> ... -> 0x408a94`
  - `trace/entry_trace.txt` 末尾: `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x40b010`: `fgets(sp+0x20, 0x2710, s2)` 读取请求行
  - `0x40b048` / `0x40b098` / `0x40b0f4`: 连续 `strsep` 解析请求行 token
  - `0x40c3b8`: `lw s3, 0x2730(sp)` 取回 URI 指针
  - `0x40c3f8`: `move a0, s3`
  - `0x40c3fc`: `jalr t9`，trace 落到 `0x408998`，说明此处进入 `do_file`
  - `0x4089c4`: `move a2, a0`
  - `0x4089c8`: 格式串 `"/www/%s"`
  - `0x4089cc`: `jalr t9` 调用 `sprintf`
  - `0x4089d0`: 目标缓冲区 `addiu a0, sp, 0x18`
  - `0x4089a4`: `addiu sp, sp, -0xa8`，说明从 `sp+0x18` 到保存的 `ra@sp+0xa0` 之间只有 `0x88` 字节
  - `0x408a94`: `lw ra, 0xa0(sp)`，在已损坏栈帧上恢复返回地址并崩溃
