# 漏洞分析: wndrmac-1.0.0.10 / id:000001,sig:11,src:000004,time:45576,execs:1233,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.handle_request 0x40ceac`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x40cad0 (Host头写入s7；默认值初始化于0x40c1e0)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL pointer dereference / DoS`
- 一句话根因: `handle_request()` 在未收到 `Host` 头时让 `s7` 保持 `NULL`，随后在 `dns_hijack` 分支把它作为 `strstr()` 第一个参数使用，导致空指针解引用崩溃。
- 数据包字段 -> 变量赋值:
  - `header.Host` 缺失 -> `s7` 保持初始化值 `NULL`
  - `request.method = GET` -> 经过 `strcasecmp(fp, "get")` 命中 GET 处理路径
  - `request.prefix + request.handler_name = "/.htmaaax..."` -> 解析到 `sp+0x2730` 的 URL 指针，满足“以 `/` 开头且不是 `/shares`”的控制流条件
- 执行顺序:
  1. `handle_request()` 读取并拆分请求行，初始化 `s7 = NULL`，随后解析 URL 到栈变量。
  2. 当前数据包没有 `Host` 头，所以 `0x40cad0` 这条 `move s7, s0` 不会执行，`s7` 一直保持 `NULL`。
  3. 代码进入 `dns_hijack` 检查分支后执行 `strstr(s7, "routerlogin.net")`，对空指针解引用并触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x408120`（ELF entry）
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`
- 关键pc地址:
  - `0x40cd54 -> 0x41b078 -> 0x41b0bc -> 0x41b244`: 调用并返回 `http_access_type()`
  - `0x40cd84`: URL 与 `"/shares"` 比较失败，转入后续分支
  - `0x40ce80 -> 0x40ce98`: `config_match("dns_hijack", ...)` 返回非 0
  - `0x40cea0`: 落入 `strstr(s7, "routerlogin.net")` 前的 block，随后崩溃
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.method` 控制 GET/POST 分支，命中 `strcasecmp(fp, "get") == 0`
  - `request.prefix + request.handler_name` 形成请求 URL，解析后位于 `sp+0x2730`
  - `header.Host` 本应在 `Host:` 解析分支中写入 `s7`；当前包缺失该字段，导致 `s7 == NULL`
- 哪个函数读取了source字段:
  - `sym.handle_request` 逐行 `fgets()` 读取 HTTP 头；命中 `Host:` 分支时在 `0x40cad0` 把解析结果写入 `s7`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.handle_request` 在请求行解析阶段通过 `strsep()` 产生 URL 指针 `sp+0x2730`
  - `sym.handle_request` 在 `0x40cad0` 将 `Host:` 值保存到 `s7`；本次因字段缺失未发生写入
- 最终如何到达sink:
  - `0x40c1e0` 把 `s7` 置零
  - 当前包无 `Host` 头，`s7` 未被覆盖
  - `0x40ce80` 调用 `config_match("dns_hijack", ...)`，trace 证明返回非 0，所以 `0x40ce98` 分支未跳走
  - `0x40cea8/0x40ceac` 准备执行 `strstr(s7, "routerlogin.net")`
  - 因 `s7 == NULL`，触发 `si_addr=NULL` 的崩溃

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。崩溃不是模糊测试环境噪声，也不是单纯“崩溃点等于根因”的误判；反汇编清楚表明 `s7` 被当作 `Host` 头缓存使用，而当前输入缺失该字段，最终在 `strstr()` 中被空指针解引用。
- 当前缺失的证据:
  - 没有运行时寄存器转储直接打印 `a0 == NULL`，但 `trace` 的 `si_addr=NULL`、`s7` 的初始化/赋值逻辑、以及输入中缺失 `Host` 头，已经足以闭合证据链。
- 对当前现象的替代解释:
  - 最合理的替代解释是“超长 `handler_name` 覆盖了栈或 `gp` 后导致随机崩溃”。但现有证据不支持这一点：`http_access_type()` 正常返回，崩溃地址稳定落在 `dns_hijack`/`strstr` 路径，且 `si_addr=NULL` 更符合 `NULL` 参数而不是地址破坏。超长 URL 在本 case 中主要起控制流作用，不是直接 sink 实参来源。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `0x40cd54 -> 0x41b078 -> 0x41b0bc -> 0x41b244 -> 0x40cd68 -> 0x40cd84 -> 0x40ce80 -> 0x40ce98 -> 0x40cea0`
  - `trace/entry_trace.txt` 末尾: `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
  - `trace/usr_sbin_uhttpd.txt` 末尾与入口trace一致，确认崩溃发生在 `uhttpd`
- 关键容器日志行:
  - `container.console.log:18`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log:19`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x40c1e0`: `move s7, zero`
  - `0x40cad0`: `move s7, s0`，仅在解析到对应头字段时才执行
  - `0x41b0b4 -> 0x41b0bc -> 0x41b244`: `http_access_type(NULL, ...)` 走空入口分支，未崩溃，只写回默认端口 `"80"`
  - `0x40ce88 -> 0x40ce98`: `config_match("dns_hijack", ...)` 返回非 0，代码继续执行
  - `0x40cea4 -> 0x40ceac`: 调用 `strstr`
  - `0x40cea8`: `move a0, s7`
  - `VulPacket.json` 的 `header` 仅含 `Accept` 和 `User-Agent`，不存在 `Host`
