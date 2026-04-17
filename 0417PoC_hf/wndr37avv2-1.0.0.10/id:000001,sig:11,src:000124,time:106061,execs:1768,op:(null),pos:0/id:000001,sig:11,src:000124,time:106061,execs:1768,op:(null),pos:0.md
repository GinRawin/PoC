# 漏洞分析: wndr37avv2-1.0.0.10 / id:000001,sig:11,src:000124,time:106061,execs:1768,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_file 0x405210 (jalr -> sprintf)`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x407288 (jalr -> strsep，提取请求行中的 URI token)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出 / 返回地址覆盖
- 一句话根因: `handle_request()` 从 HTTP 请求行解析出的超长 URI 被作为 `do_file()` 的 `arg1` 传入，`do_file()` 用 `sprintf(sp+0x18, "/www/%s", uri)` 无边界写入栈缓冲区，覆盖保存的返回地址，函数返回时跳到攻击者可控数据地址 `0x61617868` 并触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `request.prefix` + `request.handler_name` -> `handle_request()` 中请求行缓冲区 `sp+0x20`
  - `request.prefix` + `request.handler_name` -> `handle_request()` 通过 `strsep` 提取出的 URI 指针 `sp+0x2734`
  - `sp+0x2734` 中的 URI -> `handle_request()` 的路径变量 `s1`
  - `s1` -> `do_file(arg1)` -> `sprintf` 的 `a2`
- 执行顺序:
  1. `handle_request()` 先用 `fgets(sp+0x20, 0x2710, client_fp)` 读取请求首行，再用 `strsep` 从中切出 URI。
  2. `handle_request()` 遍历 `mime_handlers`，最终命中默认静态文件处理表项，间接调用 `do_file(s1, response)`.
  3. `do_file()` 在 `0x405210` 调用 `sprintf("/www/%s", uri)` 把超长 URI 写入栈上 `sp+0x18`，覆盖返回地址；函数退出时在 `0x4052d8` 附近返回到 `0x61617868`，触发崩溃。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x4041e0`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`
- 关键pc地址:
  - `0x40856c`: `handle_request()` 继续遍历 `mime_handlers`
  - `0x40854c`: 从当前表项取处理函数指针 `lw t9, 0x10(s4)`
  - `0x408558`: `move a0, s1`
  - `0x4051dc`: 进入 `sym.do_file`
  - `0x405210`: `jalr t9` 调用 `sprintf`
  - `0x405230`: `move s0, v0`
  - `0x4052d8`: `do_file` 尾声，随后因返回地址被破坏而崩溃

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.method = GET` 让请求走普通静态资源处理路径，而不是 POST 相关路径。
  - `request.prefix = "/"` 与 `request.handler_name = "cc.cssaaaxhyaa..."` 共同组成请求 URI，并进入 `handle_request()` 解析缓冲区。
  - `request.handler_name` 的超长内容直接决定 `do_file()` 中 `sprintf` 的拷贝长度。
  - `header` 和 `body` 字段未看到流入本次 sink，仅是背景噪声。
- 哪个函数读取了source字段:
  - `sym.handle_request` 在 `0x407208` 调用 `fgets` 把请求行读入 `sp+0x20`。
  - 随后在 `0x407288` 调用 `strsep`，把第二个 token 解析为 URI，并存入 `sp+0x2734`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_file` 在 `0x405204` 取 `sprintf`，`0x405208` 将用户 URI 放入 `a2`，`0x405214` 以 `a0 = sp+0x18` 调用 `sprintf("/www/%s", uri)`。
- 最终如何到达sink:
  - 请求行 URI token -> `sp+0x2734` -> `s1`
  - `handle_request()` 在 `mime_handlers` 中遍历，默认静态文件表项位于 `0x10000230`，其处理函数指针为 `0x4051dc`，即 `sym.do_file`
  - `0x40854c` 载入该函数指针，`0x408558` 把 `s1` 作为 `a0`，进入 `do_file`
  - `do_file` 以无界 `sprintf` 把超长 URI 写入栈局部缓冲区，覆盖保存的 `ra`
  - 崩溃地址 `0x61617868` 可解释为攻击字符串中的 ASCII 字节片段，说明返回地址已被输入内容污染

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 不是单纯“文件不存在”或普通异常退出。`trace` 明确显示控制流进入 `do_file`，而 `do_file` 的核心危险操作是对栈缓冲区执行无界 `sprintf`。
  - `do_file` 的栈帧大小为 `0xa8`，输出缓冲区位于 `sp+0x18`，保存的 `ra` 位于 `sp+0xa0`；攻击者只需写入超过 `0x88` 字节即可覆盖返回地址，和当前超长 `handler_name` 完全匹配。
  - 崩溃发生在 `do_file` 尾声，`SIGSEGV si_addr=0x61617868` 明显是来自输入字符串的伪地址，而不是正常代码段地址。
- 当前缺失的证据:
  - 没有逐寄存器运行时快照证明 `a2` 的即时值，但现有反汇编、trace 顺序、栈布局和崩溃地址已经足以闭环。
- 对当前现象的替代解释:
  - 最合理但已被排除的替代解释是“`fopen("/www/<path>")` 失败导致异常”。实际上 `fopen` 失败只会走 `beqz v0, 0x4052d8` 返回，不会产生 `si_addr=0x61617868` 这种带有输入特征的崩溃地址；真正导致崩溃的是前面的 `sprintf` 栈溢出。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt`
    - `pc=0x40854c`
    - `pc=0x408558`
    - `pc=0x4051dc`
    - `pc=0x405218`
    - `pc=0x405230`
    - `pc=0x4052d8`
    - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61617868} ---`
  - `trace/usr_sbin_uhttpd.txt`
    - `pc=0x40856c`
    - `pc=0x40854c`
    - `pc=0x408558`
    - `pc=0x4051dc`
    - `pc=0x405218`
    - `pc=0x405230`
    - `pc=0x4052d8`
- 关键容器日志行:
  - `container.console.log`
    - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
    - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.handle_request`
    - `0x407200: addiu a0, sp, 0x20`
    - `0x407208: jalr t9` -> `fgets`
    - `0x407280: addiu a0, sp, 0x2734`
    - `0x407288: jalr t9` -> `strsep`
    - `0x40854c: lw t9, 0x10(s4)`
    - `0x408558: move a0, s1`
    - 默认静态文件处理表项在 `0x10000230/0x10000240`，函数指针为 `0x4051dc`
  - `sym.do_file`
    - `0x4051e8: addiu sp, sp, -0xa8`
    - `0x4051ec: sw ra, 0xa0(sp)`
    - `0x405204: lw t9, sym.imp.sprintf`
    - `0x405208: move a2, a0`
    - `0x405214: addiu a0, sp, 0x18`
    - `0x405210: jalr t9` -> `sprintf("/www/%s", uri)`
    - `0x4052d8: lw ra, 0xa0(sp)`，返回前使用已被覆盖的保存返回地址
