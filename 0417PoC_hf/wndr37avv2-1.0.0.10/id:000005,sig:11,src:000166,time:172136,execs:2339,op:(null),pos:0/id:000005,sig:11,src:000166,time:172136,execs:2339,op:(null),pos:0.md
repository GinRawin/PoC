# 漏洞分析: wndr37avv2-1.0.0.10 / id:000005,sig:11,src:000166,time:172136,execs:2339,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_js 0x40532c (jalr -> sprintf)`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x408558 (move a0, s1; 0x40855c jalr t9 -> sym.do_js)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出
- 一句话根因: `do_js` 把请求路径直接通过 `sprintf("/www/%s")` 写入栈上固定缓冲区 `sp+0x18`，未做长度检查，超长 `.js...` 路径覆盖返回地址并在函数返回时触发崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `handle_request.s1` -> `do_js.a0` -> `sprintf` 的 `a2`
  - `request.handler_name` 前缀为 `.js` -> 命中 `mime_handlers` 中的 JS 处理逻辑 -> 调用 `do_js`
  - `request.prefix` (`/`) -> 与 `handler_name` 共同构成实际请求路径 `/.js...`，帮助进入 URL 路径分发
- 执行顺序:
  1. `handle_request` 使用请求路径字符串做后缀/handler 匹配，命中 `.js` 对应处理函数。
  2. `handle_request` 在 `0x408558/0x40855c` 以 `a0=s1`、`a1=s2` 调用 `sym.do_js`。
  3. `do_js` 在 `0x40532c` 调用 `sprintf(sp+0x18, "/www/%s", a0)`，将超长路径写入栈缓冲区并破坏返回状态。
  4. `fopen` 因路径异常失败后直接走函数尾，返回时跳向被覆盖的地址，trace 末尾出现 `SIGSEGV`，`si_addr=0x61616160`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `sym.do_js @ 0x4052ec`
- 命中的入口trace: `0x40854c -> 0x408558 -> 0x4052ec -> 0x405334 -> 0x40534c -> 0x4054ac -> SIGSEGV`
- 子进程trace链: 无；仅使用 `trace/entry_trace.txt` 即可闭环
- 关键pc地址:
  - `0x40854c`: 取出 handler 函数指针
  - `0x408558`: `move a0, s1`
  - `0x40855c`: `jalr t9`，调用 `sym.do_js`
  - `0x405324`: `move a2, a0`
  - `0x405330`: `addiu a0, sp, 0x18`
  - `0x40532c`: `jalr t9`，实际进入 `sprintf`
  - `0x40534c`: `move s1, v0`，保存 `fopen` 返回值
  - `0x4054ac`: 函数尾基本块起点；随后返回阶段触发崩溃

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 的长字符串内容进入 `handle_request.s1`，随后作为 `do_js` 的第一个参数。
  - `request.handler_name` 的 `.js` 前缀控制 MIME/handler 选择，保证调用 `do_js`。
  - `request.prefix` 仅帮助形成实际 URL 路径，不是造成覆盖的主要内容来源。
- 哪个函数读取了source字段:
  - 具体 HTTP 解析函数未在当前允许输入中直接展开到最初赋值点；但从 `handle_request` 调用点可确认，请求路径已被解析到 `s1`，并在 `0x408558` 作为 `a0` 传入 `do_js`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_js` 在 `0x40531c` 加载格式串 `"/www/%s"`，在 `0x405324` 将攻击者可控路径放入 `a2`，在 `0x405330` 将栈缓冲区 `sp+0x18` 放入 `a0`，并于 `0x40532c` 调用 `sprintf`。
  - 该栈帧大小为 `0x130`，保存寄存器区位于高地址处；`request.handler_name` 长度为 `7491`，远超栈上局部缓冲区可承受范围。
- 最终如何到达sink:
  - `request.handler_name` -> `handle_request.s1` -> `do_js.a0` -> `sprintf("/www/%s")` -> 栈缓冲区 `sp+0x18`
  - 由于没有长度限制，格式化结果覆盖栈上的返回上下文，函数退出时跳向污染后的地址。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这不是单纯的文件不存在或空指针。`fopen` 失败后本应直接返回，但 trace 在 `do_js` 尾部后立刻出现 `SIGSEGV`，且 `si_addr=0x61616160` 明显来自输入中的 `'a'` 模式，符合栈返回地址/返回控制流被覆盖后的特征。
  - 崩溃前的关键反汇编明确显示唯一直接使用超长请求路径的危险点是 `sprintf(sp+0x18, "/www/%s", a0)`；这里没有边界检查。
- 当前缺失的证据:
  - 没有寄存器快照，无法把被覆盖后的 `ra/sp` 数值逐寄存器打印出来。
  - 没有更早的 HTTP 解析 trace，无法把 `request.handler_name` 的最初解析函数名精确标成非 `unknown`。
- 对当前现象的替代解释:
  - 最合理的替代解释是“崩溃来自别处先前的内存破坏”；但当前 trace 中 `do_js` 从进入到崩溃之间，最直接、最明显、且与用户输入长度成正比的危险写入就是这次 `sprintf`，因此替代解释不如栈溢出成立。

## 证据

- 关键trace行:
  - `pc=0x40854c`
  - `pc=0x408558`
  - `pc=0x4052ec`
  - `pc=0x405334`
  - `pc=0x40534c`
  - `pc=0x4054ac`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x40531c: lw a1, ... -> "/www/%s"`
  - `0x405320: lw t9, ... -> sym.imp.sprintf`
  - `0x405324: move a2, a0`
  - `0x405330: addiu a0, sp, 0x18`
  - `0x40532c: jalr t9`
  - `0x405340: lw t9, ... -> sym.imp.fopen`
  - `0x405348: addiu a1, ... -> "r"`
  - `0x40854c: lw t9, 0x10(s4)`
  - `0x408558: move a0, s1`
  - `0x40855c: jalr t9`
