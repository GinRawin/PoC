# 漏洞分析: wndrmacv1-1.0.0.20 / id:000008,sig:11,src:000180,time:324215,execs:3235,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_js 0x408ae8`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x40b0a4`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出 / 返回地址覆盖
- 一句话根因: `handle_request` 从 HTTP request line 提取出的超长 URL path 在命中 `.js` 分发表后被原样传给 `do_js`，`do_js` 在 `sprintf(sp+0x18, "/www/%s", path)` 中无边界写入 0x130 栈帧内的局部缓冲区，最终覆盖保存的 `ra`，函数返回时跳到 `0x61616160` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name` -> `handle_request` 中 request path token / `[sp+0x2730]` / `s3` / `do_js(a0)` / `sprintf(a2)`
  - `request.handler_name` 中前缀 `.js` -> 命中 `mime_handlers` 中 `.js` 表项，选择 `do_js`
- 执行顺序:
  1. `uhttpd` 在 `handle_request` 中用 `fgets` 读入请求行，并通过 `strsep` 在 `0x40b0a4` 解析出 path token；该 path 保存在 `[sp+0x2730]`，内容对应 `"/" + request.handler_name`。
  2. `handle_request` 在 `0x40bdf8/0x40bdfc` 用 `strstr(path, ".js")` 匹配到 `mime_handlers` 的 `.js` 表项（表项回调 `0x408aa8 = sym.do_js`），随后在 `0x40c3fc` 调用 `do_js(path, conn)`。
  3. `do_js` 在 `0x408ae8` 调用 `sprintf(sp+0x18, "/www/%s", path)` 触发栈溢出，覆盖 `ra`；返回序列到 `0x408c68` 读取被污染的 `ra`，trace 最终报 `SIGSEGV si_addr=0x61616160`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x407940`（ELF entry point）
- 命中的入口trace: `0x40bde8 -> 0x40bdf8 -> 0x40be04 -> 0x40c3bc -> 0x40c3cc -> 0x40c3ec -> 0x40c3f8 -> 0x408aa8 -> 0x408af0 -> 0x408b08 -> 0x408c68 -> SIGSEGV`
- 子进程trace链: 未见必须跟踪的子进程；仅靠 `trace/entry_trace.txt` 已足够闭合调用链
- 关键pc地址:
  - `0x40b0a4`: `strsep` 解析 request line 的 path token
  - `0x40b844`: 从 `[sp+0x2730]` 取出 path，形成后续文件路径处理变量
  - `0x40bdf8`: `strstr(path, mime_handlers[i].ext)`
  - `0x10000298`: `.js` 表项，回调指针 `0x408aa8`
  - `0x40c3fc`: `jalr t9` 调用 `do_js`
  - `0x408ae8`: `sprintf`
  - `0x408c68`: 函数返回时加载被覆盖的 `ra`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `VulPacket.request.prefix` 与 `VulPacket.request.handler_name` 共同组成请求路径 `/.jsaaa...`。
  - `request.handler_name` 的内容直接成为 `handle_request` 解析出的 path token 主体。
  - `request.handler_name` 的起始子串 `.js` 负责命中 `.js` 分发表，保证控制流进入 `do_js`。
  - `header` 与 `body` 中字段未参与本次崩溃链，最多只是噪声输入。
- 哪个函数读取了source字段:
  - `sym.handle_request` 在 `0x40b024` 先把整个 request line 读入 `sp+0x20`。
  - 随后在 `0x40b0a4` 通过 `strsep(&sp+0x2734, " ")` 解析第二个 token，同时 `[sp+0x2730]` 保留了已被 `strsep` 截断后的 path token 起始地址。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.handle_request` 在 `0x40c3b8` 把 `[sp+0x2730]` 载入 `s3`，并在 `0x40c3fc` 以 `a0=s3` 调用 `sym.do_js`。
  - `sym.do_js` 在 `0x408ae0` 将攻击者可控 path 放入 `a2`，在 `0x408ae8` 执行 `sprintf(sp+0x18, "/www/%s", a2)`。
- 最终如何到达sink:
  - 攻击者提供的 path 长度约为 `1 + 7491 = 7492` 字节（`/` 加 `handler_name`）。
  - `do_js` 中格式化目标缓冲区起点为 `sp+0x18`，保存的 `ra` 位于 `sp+0x12c`，两者间距仅 `0x114` 字节。
  - `sprintf` 额外再写入 `"/www/"` 前缀，远超 `0x114` 字节，必然覆盖保存的 `s*` 寄存器和 `ra`。
  - trace 在 `0x408c68` 的崩溃说明真正 fault site 是函数返回；根因 sink 是更早的 `sprintf` 调用点，而不是 epilogue 本身。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃信号明确：`container.console.log` 出现 `SIGSEGV`，`trace/entry_trace.txt` 末尾也显示 `SIGSEGV`。
  - 崩溃地址 `si_addr=0x61616160` 明显来自攻击者填充的 `'a'` 数据，符合返回地址/控制数据被覆盖后的间接跳转特征。
  - `do_js` 的真实危险操作是无长度限制的 `sprintf`；trace 仅在函数返回时暴露后果，不改变根因判断。
  - 控制流证据、数据流证据、崩溃现象三者一致，不能用普通空指针、环境异常或仿真误差解释。
- 当前缺失的证据:
  - 没有寄存器转储，无法逐字节展示被覆盖后的完整 `ra` 值。
  - 但 `si_addr=0x61616160` 与 `sprintf` 栈溢出已足够完成漏洞确认，不影响结论级别。
- 对当前现象的替代解释:
  - 最合理替代解释是 `fopen("/www/%s")` 失败后正常返回；但这与实际 `0x408c68` 返回阶段崩溃、以及 `0x61616160` 攻击者可控地址完全不符，因此可排除。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾:
    - `pc=0x40c3ec`
    - `pc=0x40c3f8`
    - `pc=0x408aa8`
    - `pc=0x408af0`
    - `pc=0x408b08`
    - `pc=0x408c68`
    - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.do_js 0x408ad8-0x408aec`:
    - 载入 `sprintf`
    - `a2 = a0`（调用者传入的 path）
    - `a1 = "/www/%s"`
    - `a0 = sp + 0x18`
    - `jalr t9` 调用 `sprintf`
  - `sym.do_js` 栈布局:
    - 局部格式化缓冲区起点 `sp+0x18`
    - 保存的 `ra` 在 `sp+0x12c`
    - 可安全容纳空间仅 `0x114` 字节，远小于本次 path 长度
  - `mime_handlers` 中 `.js` 表项:
    - `0x10000298: { ".js", "text/javascript", ..., 0x408aa8, ... }`
  - `sym.handle_request 0x40bdf8-0x40c3fc`:
    - `strstr(path, ".js")` 选择 `.js` 表项
    - `lw s3, 0x2730(sp)` 后在 `0x40c3fc` 以 `a0=s3` 调用 `do_js`
