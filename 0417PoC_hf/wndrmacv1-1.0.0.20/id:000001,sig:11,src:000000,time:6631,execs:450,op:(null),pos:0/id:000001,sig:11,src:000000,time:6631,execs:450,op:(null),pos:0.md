# 漏洞分析: wndrmacv1-1.0.0.20 / id:000001,sig:11,src:000000,time:6631,execs:450,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_asp@0x004119d8 0x00411a20`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0xunknown`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `栈缓冲区溢出`
- 一句话根因: `do_asp()` 在 `0x00411a20` 用 `sprintf(sp+0x18, "/www/%s", attacker_path)` 将攻击者可控的超长请求路径无边界写入栈缓冲区，覆盖保存的 `ra`，函数返回时在 `0x00411d48` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `HTTP请求路径后缀/页面名` -> `sym.do_asp` 的 `a0`
  - `request.prefix` -> `请求路由选择字符串` -> 帮助进入处理该页面名的控制流
- 执行顺序:
  1. `uhttpd` 在 `main(0x00407cd4)` 中接收请求并进入 `handle_request(0x0040afd4)`。
  2. 请求路径被继续传入 `do_asp(0x004119d8)`，在 `0x00411a20` 执行 `sprintf(sp+0x18, "/www/%s", a0)`。
  3. 超长 `handler_name` 覆盖 `sp+0x4c4` 处保存的返回地址，`do_asp` 在 `0x00411d48` 取回被污染的 `ra` 时触发 `SIGSEGV`，`si_addr=0x61616160`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x00407cd4`
- 命中的入口trace: `main(0x00407cd4)` -> `handle_request(0x0040afd4)` -> `init_lang_table(0x0040cea0)` -> `lang_filename(0x0040fea0)` -> `do_asp(0x004119d8)` -> crash
- 子进程trace链: `无，入口trace已能闭合崩溃路径`
- 关键pc地址:
  - `0x00407cd4`: `main`
  - `0x0040cea0`: `init_lang_table`
  - `0x0040fea0`: `lang_filename`
  - `0x004119d8`: `do_asp` 入口
  - `0x00411a20`: `sprintf`
  - `0x00411d48`: 函数尾声，读取被破坏的保存现场后崩溃

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 提供了超长页面名内容，内容中大量 `'a'` 直接体现在崩溃地址 `0x61616160` 中。
  - `request.prefix` 为 `/upgrade_check.cgi`，用于命中对应请求处理路径；它本身不是覆盖返回地址的主要内容源。
- 哪个函数读取了source字段:
  - 精确的“读取并赋值到局部变量”的 caller 指令未完全恢复；当前能确认的是 `handle_request` 之后传给 `do_asp(a0)` 的页面名来自本次 HTTP 请求路径，且与 `VulPacket.json` 中的 `request.handler_name` 一致地表现为超长 `.html...aaaa...` 后缀。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_asp@0x004119d8` 在 `0x00411a20` 调用 `sym.imp.sprintf`，参数为:
  - 目标缓冲区: `sp+0x18`
  - 格式串: `0x00446278 -> "/www/%s"`
  - 源参数: `a0`，即 caller 传入的请求页面名
- 最终如何到达sink:
  - `request.handler_name` 的超长内容作为 `do_asp(a0)` 进入 `sprintf("/www/%s", a0)`。
  - `do_asp` 栈帧大小为 `0x4c8`，保存的 `ra` 位于 `sp+0x4c4`。
  - 目标缓冲区从 `sp+0x18` 开始，到保存的 `ra` 相距 `0x4ac` 字节；超长输入越界写穿该距离后覆盖返回地址。
  - 函数结束时在 `0x00411d48` 执行 `lw ra, 0x4c4(sp)`，取出已被污染的值并崩溃。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这不是单纯的文件打开失败或空指针误报。崩溃点虽在函数尾声，但反汇编显示此前存在明确的无界 `sprintf`，且崩溃地址 `0x61616160` 与输入中的 `'a'` 模式吻合，符合典型“栈返回地址被用户数据覆盖”特征。
- 当前缺失的证据:
  - `handle_request` 内把请求路径具体装入 `do_asp(a0)` 的单条赋值指令未精确定位，因此 `Source位置` 的精确地址只能写 `unknown`。
- 对当前现象的替代解释:
  - 替代解释如“`fopen("/www/%s")` 失败导致异常返回”不成立，因为真正异常发生在 `sprintf` 之后的函数尾声，且 `si_addr=0x61616160` 指向用户可控字节模式，不符合普通 `fopen` 失败路径。

## 证据

- 关键trace行:
  - `pc=0x4119d8`
  - `pc=0x411a28`
  - `pc=0x411a44`
  - `pc=0x411d48`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x00411a20: jalr t9` 调用 `sym.imp.sprintf`
  - `0x00411a24: addiu a0, sp, 0x18`
  - `0x00411a1c: addiu a1, a1, 0x6278`，对应字符串 `"/www/%s"`
  - `0x00411a18: move a2, a0`，将 caller 传入的请求页面名作为 `%s` 实参
  - `0x004119e4: addiu sp, sp, -0x4c8`
  - `0x004119e8: sw ra, 0x4c4(sp)`
  - `0x00411d48: lw ra, 0x4c4(sp)`，崩溃发生在读取被覆盖的保存返回地址时
