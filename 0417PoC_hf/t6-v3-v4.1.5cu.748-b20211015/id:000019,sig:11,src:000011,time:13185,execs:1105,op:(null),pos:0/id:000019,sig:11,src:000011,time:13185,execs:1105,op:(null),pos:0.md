# 漏洞分析: t6-v3-v4.1.5cu.748-b20211015 / id:000019,sig:11,src:000011,time:13185,execs:1105,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/bin/lighttpd 0x40c1f0 0x40c2e4 (调用 0x404980 -> strcpy)`
- Source位置: `/bin/lighttpd 0x40c1f0 0x40c2cc-0x40c2d4 (从连接对象偏移 0x110 取出 Host 字符串指针)`
- 漏洞二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/T6/T6/debug/fs/bin/lighttpd`
- 漏洞类型: 栈缓冲区溢出 / 越界写导致的非法指针解引用崩溃
- 一句话根因: 代码把可控的 `Host` 字符串直接 `strcpy` 到栈上 256 字节缓冲区 `s8+124`，超长输入覆盖了同一栈帧中的保存参数，随后被污染的连接指针传入 `0x40b30c` 并在 `0x40b348` 解引用时触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `header.host` -> `*(conn + 0x110) -> *( *(conn + 0x110) ) -> strcpy(dst=s8+124, src=host)`
  - `request.handler_name` -> `*(conn + 0x140)`，用于与白名单字符串做 `strstr` 比较，决定是否走到脆弱的 Host 复制分支
- 执行顺序:
  1. `0x40c1f0` 先遍历白名单页面名，对 `*(conn + 0x140)` 做 `strstr` 检查；当前请求路径不命中白名单，继续执行。
  2. `0x40c2cc-0x40c2e4` 取出 `*(conn + 0x110)` 指向的 Host 字符串，调用 `strcpy` 复制到栈缓冲区 `s8+124`。
  3. 超长 Host 覆盖栈上的保存参数；返回后 `0x40c2ec` 读出被污染的 `a0` 传入 `0x40b30c`，`0x40b348` 再解引用该伪造指针并在 `si_addr=0x616162d9` 处崩溃。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/T6/T6/debug/fs/bin/lighttpd`
- Main地址: `unknown`
- 命中的入口trace: `trace/entry_trace.txt:2635-2649`
- 子进程trace链: `无；崩溃发生在入口进程 lighttpd 自身`
- 关键pc地址:
  - `0x40c1f0`: 漏洞函数起点
  - `0x40c2cc`: 读取 `conn+0x110`
  - `0x404980`: `strcpy@plt`
  - `0x40c2ec`: 从当前栈帧重新取出参数并调用下游函数
  - `0x40b30c`: 使用连接对象解析字段的函数
  - `0x40b348`: 解引用被污染指针，触发崩溃

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `header.host` 长度为 `1248`，控制 `*(conn + 0x110)` 指向的字符串内容，并直接流入 `strcpy` 的源参数。
  - `request.handler_name` 长度为 `1021`，参与形成请求 URL，并控制 `*(conn + 0x140)` 的内容；该字段不直接写入 sink，但影响是否绕过白名单检查到达 sink。
- 哪个函数读取了source字段:
  - `0x40c1f0` 在 `0x40c2cc-0x40c2d4` 执行 `lw v0,272(v0); lw v0,0(v0)`，取出连接对象偏移 `0x110` 处保存的字符串指针。结合后续 `sprintf(..., "http://%s/index.html", buffer)` 可知这是 Host 字段。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `0x40c1f0` 在 `0x40c2e4` 调用 `strcpy`，把 Host 字符串写入栈缓冲区 `s8+124`。
  - 同一函数稍后在 `0x40c32c` 调用 `sprintf`，使用格式串 `http://%s/index.html` 拼接该 Host；但程序在更早的参数污染阶段已经进入异常状态。
- 最终如何到达sink:
  - `header.host`
  - `-> conn + 0x110`
  - `-> 0x40c2e4 strcpy(dst=s8+124, src=host)`
  - `-> 覆盖 256 字节缓冲区之后的栈内容，包括 0x40c1f0 保存的 a0/s8/ra`
  - `-> 0x40c2ec lw a0,432(s8)` 取回已被污染的连接指针
  - `-> 0x40b30c`
  - `-> 0x40b348/0x40b34c` 解引用伪造指针并崩溃

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。入口 trace 明确显示执行顺序为 `0x40c1f0 -> 0x404980(strcpy) -> 0x40b30c -> 0x40b348 -> SIGSEGV`。`strcpy` 前目的缓冲区只有 `256` 字节，而请求中的 `Host` 长度为 `1248`，足以覆盖后续栈槽。崩溃地址 `0x616162d9` 也符合被攻击者数据污染后的非法指针形态。
- 当前缺失的证据:
  - 没有寄存器快照可直接展示 `0x40c2ec` 读出的 `a0` 被覆写后的具体值；但现有 trace、反汇编和长度对比已足以闭合因果链。
- 对当前现象的替代解释:
  - 最合理的替代解释是其他请求字段先前破坏了连接对象，再在 `0x40b348` 暴露；但这与 trace 顺序不符，因为崩溃前刚执行过 `strcpy(host -> stack)`，且该写入本身就能覆盖后续要读取的参数槽。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt:2635-2649`
  - `pc=0x40c1f0`
  - `pc=0x40c2cc`
  - `pc=0x404980`
  - `pc=0x40c2ec`
  - `pc=0x40b30c`
  - `pc=0x40b348`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x616162d9} ---`
- 关键容器日志行:
  - `2026-04-14 02:41:56: (log.c.97) server started`
- 关键反编译证据:
  - `0x40c220-0x40c230`: `memset(s8+124, 0, 0x100)`，说明目的缓冲区大小是 `256` 字节
  - `0x40c2cc-0x40c2e4`: 从 `conn+0x110` 读取字符串后调用 `strcpy`
  - `0x40c31c-0x40c32c`: 使用格式串 `http://%s/index.html` 调用 `sprintf`，佐证 `conn+0x110` 为 Host
  - `0x40b30c-0x40b34c`: 下游函数进入后立即从传入的 `a0` 解引用 `a0+0x178`
  - `0x404980 -> strcpy`, `0x404d90 -> strstr`, `0x404f40 -> memset`, `0x405030 -> sprintf`, `0x405140 -> strlen`
