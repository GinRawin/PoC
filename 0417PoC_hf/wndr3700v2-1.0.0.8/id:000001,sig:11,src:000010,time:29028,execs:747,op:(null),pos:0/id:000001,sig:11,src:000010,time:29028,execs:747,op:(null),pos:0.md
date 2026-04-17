# 漏洞分析: wndr3700v2-1.0.0.8 / id:000001,sig:11,src:000010,time:29028,execs:747,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_asp 0x00422014 (jalr sym.imp.sprintf)`，崩溃表现于 `0x0042233c`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x00408558 (move a0, s1)`；更早的请求行读取发生在 `0x004071f4`，并通过 `strsep` 在 `0x0040722c/0x004072d8` 解析 HTTP request line
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出
- 一句话根因: `do_asp()` 将攻击者可控的超长请求路径用 `sprintf("/www/%s", path)` 直接写入栈上 `sp+0x18` 缓冲区，覆盖保存的返回地址，返回时跳到 `0x61616160` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `handle_request` 中的路径变量 `s1`
  - `request.handler_name` -> `do_asp` 的 `arg1/a0`
  - `request.handler_name` -> `do_asp` 栈缓冲区 `sp+0x18`
- 执行顺序:
  1. `handle_request` 处理 HTTP 请求并在 `0x408558` 将路径变量 `s1` 作为 `a0` 传给 `do_asp`
  2. `do_asp` 在 `0x422014` 调用 `sprintf(sp+0x18, "/www/%s", a0)`，把 7498 字节路径写入距离保存 `ra` 仅 1196 字节的栈缓冲区
  3. 函数尾声使用被覆盖的返回地址，最终跳转到 `0x61616160`，触发 `SIGSEGV`

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x004041e0`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: 未见必须跟踪的子进程；当前崩溃链已在入口二进制内闭合
- 关键pc地址:
  - `0x404ed8 -> 0x404ef0`: `handle_request` 调用者返回路径
  - `0x40854c`: 取出 `do_asp` 函数指针
  - `0x408558`: `move a0, s1`
  - `0x421fcc`: 进入 `do_asp`
  - `0x422000`: `move s6, a1`
  - `0x42201c`: `sprintf` 返回后恢复 `gp`
  - `0x422038`: `fopen` 返回，因失败直接走函数尾声
  - `0x42233c`: 进入函数尾声，随后因被污染返回地址崩溃

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `VulPacket.json` 中 `request.handler_name` 是唯一明显超长、且与 ASP 路径匹配的输入字段，长度为 `7493`
  - `request.method = GET` 和 `request.version = 1.1` 只负责让请求被正常解析
  - `request.handler_name` 控制 `handle_request` 里的路径变量 `s1`，并作为 `do_asp` 的第一个参数传入
- 哪个函数读取了source字段:
  - `sym.handle_request` 在 `0x4071f4` 先把 HTTP request line 读入栈上缓冲区 `sp+0x20`
  - 随后在 `0x40722c`、`0x4072d8` 调用 `strsep` 对 request line 分段，继续在 `handle_request` 内传播，最终由 `s1` 保存待处理路径
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.handle_request` 在 `0x408558` 执行 `move a0, s1`，把路径变量传给 `sym.do_asp`
  - `sym.do_asp` 在 `0x422008` 取 `sprintf`，并在 `0x422014` 执行 `sprintf(sp+0x18, "/www/%s", a0)`
- 最终如何到达sink:
  - `do_asp` 栈帧大小为 `0x4c8`
  - 本地路径缓冲区起始于 `sp+0x18`
  - 保存的返回地址位于 `sp+0x4c4`
  - 因此 `sp+0x18` 到保存 `ra` 的距离仅 `0x4ac = 1196` 字节
  - 实际写入长度为 `len("/www/") + len(handler_name) + 1 = 5 + 7493 + 1 = 7499` 字节
  - 溢出至少 `7499 - 1196 = 6303` 字节，足以覆盖保存的 `ra`
  - 崩溃时 `si_addr = 0x61616160`，与攻击载荷中的 `'a'` 模式一致，说明函数返回地址已被输入内容改写

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃不是偶发的 `fopen` 失败或空指针问题，而是发生在 `do_asp` 返回路径
  - 真正危险点是 `sprintf` 对固定栈缓冲区的无界写入；崩溃点 `0x42233c` 只是溢出后的表现
  - 攻击数据、调用链、栈布局和崩溃地址可以相互印证，已经满足 `source -> variable -> sink` 闭环
- 当前缺失的证据:
  - 没有寄存器转储，无法逐寄存器展示 `ra` 被覆盖前后的值
  - 但这不影响根据 trace、反汇编和长度计算确认漏洞
- 对当前现象的替代解释:
  - 最合理的替代解释是路径不存在导致 `fopen` 失败后正常返回
  - 该解释无法说明 `si_addr = 0x61616160`，也无法解释为什么恰好在 `sprintf` 后立即进入尾声并崩溃，因此不成立

## 证据

- 关键trace行:
  - `pc=0x404ed8`
  - `pc=0x404ef0`
  - `pc=0x40854c`
  - `pc=0x408558`
  - `pc=0x421fcc`
  - `pc=0x422000`
  - `pc=0x42201c`
  - `pc=0x422038`
  - `pc=0x42233c`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x00408558: move a0, s1`
  - `0x0040855c: jalr t9`，其中 `t9 = [s4+0x10] = 0x421fcc (sym.do_asp)`
  - `0x00422018: addiu a0, sp, 0x18`
  - `0x00422010: addiu a1, a1, -0x44a8`，格式串为 `"/www/%s"`
  - `0x00422014: jalr t9`，调用 `sym.imp.sprintf`
  - `0x00421fdc: sw ra, 0x4c4(sp)`，保存返回地址
  - `0x0042233c: lw ra, 0x4c4(sp)`，函数尾声取回已被覆盖的返回地址
