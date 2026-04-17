# 漏洞分析: wndr37avv2-1.0.0.10 / id:000010,sig:11,src:000003,time:975511,execs:5312,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.do_asp 0x422014`
- Source位置: `/usr/sbin/uhttpd sym.handle_request 0x40722c`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出
- 一句话根因: `handle_request()` 将 HTTP URL 派生出的超长字符串传给 `do_asp()`，后者在 `0x422014` 用 `sprintf("/www/%s", attacker_str)` 写入栈上 `sp+0x18` 缓冲区，覆盖保存返回地址，最终跳转到攻击者可控的 `0x61616160` 并崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `handle_request()` 中 URL 派生指针 `[sp+0x2730]` -> `s1` (`0x408514`) -> `a0` (`0x408558`) -> `do_asp()` 的 `sprintf` 源字符串
  - `request.handler_name` 中的 `.htm` 子串 -> `handle_request()` 中 `strstr(s1, ".htm")` (`0x407c68`/`0x407c74`) 的命中条件
- 执行顺序:
  1. `handle_request()` 先用 `fgets` 读取请求行，再在 `0x40722c` 起通过 `strsep` 拆分 URL 相关 token，并在 `0x4079bc`/`0x4079ec`/`0x407a18` 归一化为后续页面名/参数指针。
  2. 归一化后的 URL 字符串在 `0x407c68` 被 `strstr(s1, ".htm")` 命中，流程进入 `.htm` 页面处理，再在 `0x408514` 把 `[sp+0x2730]` 重新装入 `s1`，并于 `0x408558` 调用 `do_asp(s1, ...)`。
  3. `do_asp()` 在 `0x422014` 调用 `sprintf` 将攻击者字符串拼到 `/www/` 后写入栈缓冲区；返回路径上的保存 `ra` 被覆盖，函数退出时装载出攻击者值并最终跳到 `0x61616160`，触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndr37avv2-1.0.0.10/wndr37avv2_1.0.0.10/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x404574`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/entry_trace.txt` 第 209-214 行显示 `24 fork() = 26` 后进入子进程；`trace/usr_sbin_uhttpd.txt` 复现了相同尾部 PC 链并在 `0x42233c` 后崩溃
- 关键pc地址:
  - `0x4041e0`: ELF 入口地址
  - `0x404574`: `main`
  - `0x4071b8`: `handle_request`
  - `0x407c68`: `strstr(s1, ".htm")`
  - `0x40854c` / `0x40855c`: 调用 `do_asp`
  - `0x421fcc`: `do_asp` 入口
  - `0x422014`: `sprintf` 调用点
  - `0x42233c`: `do_asp` 退出基本块起点，随后使用已损坏的返回地址

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 是唯一一个既包含超长可控数据又包含 `.htm` 的字段。它控制了 `handle_request()` 中的 URL 派生字符串，并同时满足 `0x407c68` 的 `.htm` 分支条件。
  - `request.prefix` 为请求外层路由前缀，但从当前 trace 和反汇编里无法单独精确还原它在 `uhttpd` 内部对应的寄存器或局部变量，因此在二进制级别记为 `unknown`。
- 哪个函数读取了source字段:
  - `sym.handle_request` 在 `0x4071f4`-`0x40720c` 用 `fgets` 读取请求行，在 `0x40722c`、`0x407280`、`0x4072d8` 起连续用 `strsep` 拆分方法、URL、版本。之后 URL 相关 token 被进一步规范化。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.do_asp` 在 `0x422000` 取得调用者传入的攻击者字符串，在 `0x422014` 调用 `sprintf`，目标缓冲区是 `sp+0x18`，格式串是 `"/www/%s"`。
- 最终如何到达sink:
  - `request.handler_name` 的内容进入 `handle_request()` 的 URL 派生指针 `[sp+0x2730]`
  - `[sp+0x2730]` 在 `0x408514` 被重新装入 `s1`
  - `0x408558` / `0x40855c` 把 `s1` 作为 `a0` 传入 `do_asp`
  - `do_asp` 在 `0x422014` 以 `sprintf("/www/%s", a0)` 写入栈缓冲区
  - `do_asp` 的本地缓冲区起始于 `sp+0x18`，保存返回地址位于 `sp+0x4c4`，两者间距 `0x4ac = 1196` 字节；考虑格式串常量 `/www/` 和结尾空字节，安全输入上限仅约 `1190` 字节，而 `request.handler_name` 长度为 `7492`，必然覆盖保存返回地址
  - 崩溃地址 `0x61616160` 与输入中的连续 `a` 模式一致，说明返回地址已被攻击者数据污染

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这不是单纯的“文件不存在”或普通异常退出。`fopen` 失败只会走到 `0x42233c` 的退出路径；真正导致 `SIGSEGV` 的是保存返回地址已被覆盖成攻击者模式值，函数返回时跳转到 `0x61616160`。
  - 崩溃链同时具备三类证据: 容器日志中的 `SIGSEGV`、trace 中的异常地址 `0x61616160`、以及 `sprintf` 对固定栈缓冲区的无界写入。
- 当前缺失的证据:
  - 当前没有运行时寄存器转储，无法直接在崩溃现场打印 `a0` 或 `ra` 的实时值。
  - 当前也没有原始 HTTP 报文文本，因此 `request.prefix` 与 `request.handler_name` 在请求行中的精确拼接方式只能做有限推断。
- 对当前现象的替代解释:
  - 最合理的替代解释是“`fopen("/www/...")` 失败后正常返回”，但这无法解释 `si_addr=0x61616160` 这种明显来自攻击者输入模式的地址，因此不能成立。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 第 209-214 行: `24 fork() = 26`，说明崩溃发生在请求处理子进程
  - `trace/entry_trace.txt` 第 420-429 行: `0x404ed8 -> 0x404ef0 -> 0x40854c -> 0x421fcc -> 0x422000 -> 0x42201c -> 0x422038 -> 0x42233c -> SIGSEGV`
  - `trace/usr_sbin_uhttpd.txt` 第 424-429 行: 与入口 trace 尾部一致，最终 `si_addr=0x61616160`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.handle_request 0x40722c`: `strsep` 开始拆分请求行里的 URL token
  - `sym.handle_request 0x4079bc` / `0x4079ec` / `0x407a18`: 将 URL token 规范化为后续页面名/参数指针
  - `sym.handle_request 0x407c68`-`0x407c78`: `strstr(s1, ".htm")`，说明 `.htm` 子串负责把控制流送入页面处理路径
  - `sym.handle_request 0x408514`: 从 `[sp+0x2730]` 取回攻击者可控指针到 `s1`
  - `sym.handle_request 0x408558`-`0x40855c`: 以 `a0=s1` 调用 `sym.do_asp`
  - `sym.do_asp 0x422014`: 调用 `sprintf`，目标是 `sp+0x18`，格式串是 `"/www/%s"`
  - `sym.do_asp 0x42203c`: `fopen` 失败会直接跳到退出块 `0x42233c`
  - `sym.do_asp 0x42233c` 起: 开始恢复保存寄存器；结合 `si_addr=0x61616160`，可知返回地址已经被前面的溢出破坏
