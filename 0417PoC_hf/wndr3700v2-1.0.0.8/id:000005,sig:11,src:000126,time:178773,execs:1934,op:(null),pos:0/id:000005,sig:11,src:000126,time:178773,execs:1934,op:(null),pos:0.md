# 漏洞分析: wndr3700v2-1.0.0.8 / id:000005,sig:11,src:000126,time:178773,execs:1934,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_js(0x4052ec) 0x40532c`
- Source位置: `/usr/sbin/uhttpd sym.handle_request(0x4071b8) 0x4079bc`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出（覆盖保存的返回地址）
- 一句话根因: `handle_request` 将请求 URI 去掉前导 `/` 后得到的用户可控路径直接传给 `do_js`，`do_js` 用 `sprintf(sp+0x18, "/www/%s", path)` 无边界写入栈缓冲区，覆盖保存的 `ra` 并在函数退出时跳到攻击者控制地址。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> 请求 URI token -> `s0`
  - `request.handler_name` -> 去掉前导 `/` 后的路径 -> `s1`
  - `request.handler_name` -> `do_js` 的 `arg1/a0` -> `sprintf` 的 `a2`
- 执行顺序:
  1. `VulPacket.json` 中的 `GET /cc.js... HTTP/1.1` 被 `uhttpd` 解析，URI token 进入 `handle_request` 的 `s0`。
  2. `handle_request` 在 `0x4079bc` 执行 `s1 = s0 + 1` 去掉前导 `/`，随后在 MIME handler 循环中用 `strstr(s1, ".js")` 命中 `do_js` 对应表项。
  3. `handle_request` 在 `0x408558/0x40855c` 以 `a0=s1` 调用 `do_js`，`do_js` 在 `0x40532c` 执行 `sprintf(sp+0x18, "/www/%s", s1)` 发生溢出，返回时从 `0x4054ac` 取出被覆盖的 `ra`，跳向 `0x61616160` 并触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndr3700v2-1.0.0.8/wndr3700v2_1.0.0.8/debug/fs/usr/sbin/uhttpd`
- Main地址: `unknown`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`
- 关键pc地址:
  - `0x4079b8 -> 0x4079c8 -> 0x4079f4`: 处理 URI，构造 `s1`
  - `0x408008 -> 0x408024`: MIME handler 循环中执行匹配
  - `0x40854c -> 0x40855c`: 取出函数指针并以 `a0=s1` 调用 handler
  - `0x4052ec -> 0x405334`: 进入 `do_js` 并执行危险 `sprintf`
  - `0x4054ac`: 函数尾声读取被覆盖的 `ra`
  - `si_addr=0x61616160`: 攻击者可控崩溃地址

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 控制请求路径内容，本次值以 `cc.js...` 开头并包含大量 `a`。
  - `request.prefix` 仅提供前导 `/`，帮助 URI 以路径形式进入处理逻辑，但不承载溢出主体。
  - `header` 与 `body` 字段未见进入本次 sink 的证据。
- 哪个函数读取了source字段:
  - `sym.handle_request` 读取并解析请求行中的 URI；在 `0x4079bc` 执行 `addiu s1, s0, 1`，将用户路径去掉前导 `/` 后保存到 `s1`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_js` 在 `0x405324` 执行 `move a2, a0`，把调用者传入的用户路径作为 `sprintf` 第三个参数。
  - `sym.do_js` 在 `0x405328` 装载格式串 `"/www/%s"`。
  - `sym.do_js` 在 `0x40532c` 调用 `sprintf`，delay slot `0x405330` 设置目标缓冲区 `a0 = sp + 0x18`。
- 最终如何到达sink:
  - `handle_request` 中 URI token -> `s0`
  - `0x4079bc`: `s1 = s0 + 1`
  - MIME handler 循环中 `strstr(s1, ".js")` 命中 `.js` 处理项
  - `0x40854c`: 从匹配表项加载 handler 函数指针 `0x4052ec`
  - `0x408558/0x40855c`: 以 `a0=s1, a1=s2` 调用 `do_js`
  - `0x405324/0x40532c`: `sprintf(sp+0x18, "/www/%s", s1)`
  - `do_js` 栈帧大小为 `0x130`，保存的 `ra` 在 `sp+0x12c`，距离写入起点 `sp+0x18` 为 `0x114` 字节；超长路径足以覆盖返回地址

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。崩溃并非偶然空指针或环境异常，而是经典的栈溢出控制流劫持迹象：`do_js` 明确对栈缓冲区执行无界 `sprintf`，输入参数直接来自请求 URI，最终 `si_addr=0x61616160` 对应用户输入中的 `'a'` 模式，说明保存的返回地址已被可控数据覆盖。
- 当前缺失的证据:
  - 没有寄存器转储直接显示 `a0/a2` 的运行时字符串内容，但静态调用链、trace 顺序和崩溃地址已经足以闭合证据链。
- 对当前现象的替代解释:
  - 最合理的替代解释是路径字符串在别处先被破坏后再传入 `do_js`；但当前反汇编显示 `do_js` 自身第一次关键写入就是对 `sp+0x18` 的 `sprintf`，且崩溃在函数尾声读取返回地址时出现，和该栈溢出完全一致，因此替代解释不成立。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt`: `pc=0x40854c`, `pc=0x408558`, `pc=0x4052ec`, `pc=0x405334`, `pc=0x40534c`, `pc=0x4054ac`
  - `trace/entry_trace.txt`: `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
  - `trace/usr_sbin_uhttpd.txt`: `0x4079b8 -> 0x4079c8 -> 0x4079f4 -> 0x408008 -> 0x408024 -> 0x40854c -> 0x408558 -> 0x4052ec -> 0x4054ac`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.handle_request @ 0x4079bc`: `addiu s1, s0, 1`
  - `sym.handle_request @ 0x4079f4`: 后续以 `s1` 继续路径处理
  - `sym.handle_request @ 0x408558`: `move a0, s1`
  - `sym.handle_request @ 0x40855c`: `jalr t9`
  - `sym.do_js @ 0x4052f8`: `addiu sp, sp, -0x130`
  - `sym.do_js @ 0x4052fc`: `sw ra, 0x12c(sp)`
  - `sym.do_js @ 0x405324`: `move a2, a0`
  - `sym.do_js @ 0x405328`: 格式串 `"/www/%s"`
  - `sym.do_js @ 0x40532c`: `jalr t9` 调用 `sprintf`
  - `sym.do_js @ 0x405330`: `addiu a0, sp, 0x18`
  - `sym.handle_request` 的 MIME 匹配字符串: `".js"`
