# 漏洞分析: wndr3700v2-1.0.0.8 / id:000004,sig:11,src:000030,time:134963,execs:1711,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_file 0x405210`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x407220`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `栈缓冲区溢出 / sprintf`
- 一句话根因: `handle_request` 将攻击者可控的超长请求路径分派给 `.gif` 静态文件处理器 `do_file`，后者使用 `sprintf(sp+0x18, "/www/%s", path)` 将约 7.5KB 路径写入 144 字节栈缓冲区，破坏返回地址并在函数尾声崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `handle_request` 中的 `[sp+0x2730]` / `s1`（解析后的请求路径）
  - `request.method` -> `handle_request` 中 `sp+0x20` 请求行缓冲区里的方法字段（影响是否走 POST 精确匹配分支）
  - `request.handler_name` 前缀 `.gif` -> `mime_handlers` 中 `.gif -> image/gif -> do_file` 表项命中条件
- 执行顺序:
  1. `handle_request` 用 `fgets(sp+0x20, 0x2710, s2)` 读取请求行，并用 `strsep` 将路径字段放入 `[sp+0x2730]`。
  2. `handle_request` 遍历 `mime_handlers`，对 GET 请求用 `strstr(s1, ".gif")` 命中 `.gif` 表项，并以 `a0=s1, a1=s2` 调用 `do_file`。
  3. `do_file` 在 `0x405210` 调用 `sprintf(sp+0x18, "/www/%s", a0)`，写坏栈上的保存寄存器；随后 `fopen` 失败走到 `0x4052d8`，恢复 `ra` 时因栈已损坏触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `entry 0x4041e0`, 请求处理函数 `sym.handle_request 0x4071b8`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`；入口 trace 中出现 `fork()` 后，后续崩溃路径仍落在 `uhttpd` 地址空间，无需额外子进程 trace
- 关键pc地址:
  - `0x4071b8` `handle_request`
  - `0x408004` 装载 `mime_handlers`
  - `0x408034` 检查 `strstr(s1, handler)` 结果
  - `0x40854c` 取表项回调指针
  - `0x408558` 以 `a0=s1, a1=s2` 调用处理函数
  - `0x4051dc` `do_file`
  - `0x405210` `sprintf`
  - `0x405230` `fopen` 返回后
  - `0x4052d8` 函数尾声崩溃点

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 的 7492 字节内容进入请求路径变量 `[sp+0x2730]`，之后在 `0x408514` 被恢复到 `s1`，并在 `0x408558` 作为 `a0` 传给 `do_file`
  - `request.method = GET` 使 `strcasecmp(method, "post") != 0`，从 `0x408054` / `0x40806c` 走非 POST 分支
  - `request.handler_name` 以 `.gif` 开头，使 `strstr(s1, ".gif")` 在 `0x40801c` 返回非空，从而命中 `.gif` 表项；对应表项位于 `mime_handlers`，字符串为 `.gif`，内容类型为 `image/gif`，回调为 `0x4051dc`
- 哪个函数读取了source字段:
  - `sym.handle_request`
  - `0x407220-0x407238`: `strsep(&[sp+0x2730], delim)` 基于 `sp+0x20` 请求行缓冲区分离 token
  - `0x407260-0x407274`: 跳过空格后将 `[sp+0x2730]` 更新为路径 token
  - `0x408514`: `lw s1, 0x2730(sp)`，将解析后的路径装入 `s1`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_file`
  - `0x405208`: `move a2, a0`
  - `0x40520c`: 格式串装载为 `"/www/%s"`
  - `0x405210`: `jalr t9` 调用 `sprintf`
  - 目标缓冲区是 `sp+0x18`，位于 `do_file` 168 字节栈帧内；其上方保存了 `s0/s1/ra`
- 最终如何到达sink:
  - `request.handler_name` 超长内容 -> `[sp+0x2730]` -> `s1` -> `a0`(调用 `do_file`) -> `a2`(调用 `sprintf`) -> `sprintf(sp+0x18, "/www/%s", a2)`
  - 由于 `handler_name` 长度约 7492 字节，远超 `sp+0x18` 可容纳范围，覆盖 `do_file` 栈上的保存寄存器
  - `fopen("/www/<long path>", "r")` 返回空后，`do_file` 直接进入尾声；在 `0x4052d8` 执行 `lw ra, 0xa0(sp)` 时，`sp` 已关联到被破坏的栈内容，触发 `SIGSEGV`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃点、调用链、实际 sink 和攻击者输入都能闭环对应
  - `0x4052d8` 只是被破坏栈上的崩溃表现，真实危险点是 `0x405210` 的 `sprintf`
  - 攻击数据不是只影响日志或错误页，而是直接作为 `%s` 实参进入栈缓冲区格式化
  - 命中 `.gif` 处理器的控制流条件也可由请求内容解释：GET 请求且路径包含 `.gif`
- 当前缺失的证据:
  - 无关键缺失证据；现有 trace、反汇编、数据包内容已足够支撑确认
- 对当前现象的替代解释:
  - 最合理的替代解释是 `fopen` 失败导致正常错误返回，但这无法解释 `0x4052d8` 对非法地址 `0x78687960` 的访问；只有先前栈被 `sprintf` 覆盖才能解释该崩溃形态

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x405230`, `pc=0x4052d8`, `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x78687960} ---`
  - `trace/usr_sbin_uhttpd.txt` 末尾执行序列: `0x404ed8 -> 0x404ef0 -> 0x40854c -> 0x408558 -> 0x4051dc -> 0x405218 -> 0x405230 -> 0x4052d8`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `handle_request 0x407220`: `strsep(&[sp+0x2730], delim)` 从请求行解析 token
  - `handle_request 0x408514`: `lw s1, 0x2730(sp)`
  - `handle_request 0x40801c/0x408034`: `strstr(s1, ".gif")` 非空才继续
  - `mime_handlers @ 0x10000230`: 表项字符串 `.gif`，内容类型 `image/gif`，回调 `0x4051dc`
  - `handle_request 0x408558-0x408560`: `a0=s1, a1=s2` 调用 `do_file`
  - `do_file 0x40520c-0x405214`: `sprintf(sp+0x18, "/www/%s", a0)`
  - `do_file 0x405234`: `beqz v0, 0x4052d8`，`fopen` 失败后直接进入尾声
