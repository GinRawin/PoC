## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈溢出 / 非法回退缓冲区触发的 `strcpy`
- Source位置:
  - `0x43a074` `nvram_get("PWD_answer1")`
  - `0x43a0a8` `nvram_get("PWD_answer2")`
  - 当返回值为 `NULL` 时，分别在 `0x43a088` 和 `0x43a0bc` 把 `v0` 改成 `0x46c77c`
- Sink位置:
  - `0x43a098` `strcpy(sp+0x18, v0)`
  - `0x43a0d0` `strcpy(sp+0x98, v0)`
- 一句话根因: 安全问题校验逻辑在 `PWD_answer1/2` 缺失时，没有回退到合法字符串，而是把 `0x46c77c` 这一片连续 `0xff` 数据当作 C 字符串传给 `strcpy`，覆盖两个 128 字节栈缓冲区并破坏后续执行。
- 数据包字段 -> 变量赋值:
  - `packet_2.request.method=GET`, `packet_2.request.handler_name=debuginfo.htm` -> 真实触发请求为 `GET /debuginfo.htm`
  - `packet_2.body.answer1=1` -> `0x43a038/0x43a040` 调用 `cgi_value("answer1", ...)`，返回值进入 `s0`
  - `packet_2.body.answer2=<长字符串>` -> `0x43a054/0x43a05c` 调用 `cgi_value("answer2", ...)`，返回值进入 `s1`
  - `PWD_answer1/2` 不是来自当前数据包，而是由 `0x43a074/0x43a0a8` 从 NVRAM 读取；读取失败后，源码变量 `v0` 被改写为 `0x46c77c`
- 执行顺序:
  1. `uhttpd` 入口进程 `11` 经过两次 `fork()`，崩溃发生在未 `execve()` 的 `uhttpd` 子进程内。
  2. 前一包先走了 `New_Language/lang_in_flash` 相关路径，不是最终崩溃点。
  3. 第二包 `GET /debuginfo.htm` 进入安全问题答案校验函数 `0x43a008`。
  4. 代码读取 `answer1/answer2` 到 `s0/s1`，随后读取 `PWD_answer1/2`。
  5. `PWD_answer1/2` 缺失时，`v0` 被置为 `0x46c77c`，再被 `strcpy` 复制到 `sp+0x18` 和 `sp+0x98`。
  6. 栈被破坏后，trace 在 `0x43a13c -> 0x43a154 -> 0x43a16c` 后触发 `SIGSEGV`。

## 请求与入口

- 本 case 有两个 HTTP 包:
  - `packet_1`: `POST /apply.cgi?Change_pvc_num`
  - `packet_2`: `GET /debuginfo.htm`
- 真实触发崩溃的是 `packet_2`，原因是最终崩溃函数显式读取了 `answer1` 和 `answer2`，而这些字段只出现在第二个包中。
- 入口二进制由 `trace_summary.json` 精确匹配到 `/usr/sbin/uhttpd`，`main=0x4047d4`，trace 文件为 `trace/usr_sbin_uhttpd.txt`。
- `trace/usr_sbin_uhttpd.txt` 显示 `11 -> 13 -> 15` 两次 `fork()` 后仍留在同一 `uhttpd` 映像中，期间没有 `execve()`，因此真实出问题的二进制就是 `/usr/sbin/uhttpd`。

## 执行流还原

1. `trace/usr_sbin_uhttpd.txt:340-345`：
   - `11 fork() = 13`
   - `13 fork() = 15`
   - 之后继续在同一份 `uhttpd` 代码段内执行。
2. 较早的 trace 命中了 `0x43ca24/0x43ca8c/...`，与二进制里 `New_Language`、`lang_in_flash` 字符串交叉引用一致，说明第一包主要对应语言修改路径。
3. 崩溃前最后一段关键 trace 在 `trace/usr_sbin_uhttpd.txt:690-725`：
   - `0x40b95c` 开始进入 `cgi_setobject`
   - `0x43a008` 进入安全问题答案校验函数
   - `0x43a090`、`0x43a0c4` 两次进入 `strcpy`
   - `0x43a13c -> 0x43a154 -> 0x43a16c` 后立刻 `SIGSEGV`
4. 因为这段 trace 明确读取了 `answer1/answer2` 并访问 `PWD_answer1/2`，它只能对应第二个包，而不是第一个 `apply.cgi?Change_pvc_num` 请求。

## Source -> Variable -> Sink

### 1. 数据包 source

- `0x43a030/0x43a038` 装载字符串地址 `0x45eb18`，对应 `answer1`。
- `0x43a040` 调用 `cgi_value`，delay slot `0x43a044` 把第三参数设为第二个函数参数；返回值保存在 `v0`。
- `0x43a064` 把该返回值存入 `s0`。
- `0x43a048/0x43a054` 装载字符串地址 `0x45eb24`，对应 `answer2`。
- `0x43a05c` 再次调用 `cgi_value`；`0x43a070` 把返回值存入 `s1`。

结论: 当前包中 `answer1` 和 `answer2` 被真实读取，分别落入寄存器变量 `s0`、`s1`。

### 2. 真实致崩 source

- `0x43a074`:
  - `a0 = 0x45eb14`，即 `PWD_answer1`
  - 调用 `nvram_get`
- `0x43a080` 检查返回值；若非空则直接进入 `0x43a090`
- `0x43a088/0x43a08c`：
  - 当返回值为空时，执行 `lui v0, 0x46`
  - `addiu v0, v0, -0x3884`
  - 得到回退指针 `0x46c77c`
- 第二次读取完全同构：
  - `0x43a0a8` 读取 `PWD_answer2`
  - `0x43a0bc/0x43a0c0` 在失败时同样把 `v0` 置为 `0x46c77c`

这说明真正流向 sink 的不是 `answer1/answer2` 本身，而是 `nvram_get("PWD_answer1/2")` 失败后的错误回退值 `0x46c77c`。

### 3. sink callsite 核验

- 第一次拷贝:
  - `0x43a090` 取 `strcpy@plt`
  - `0x43a094` 设 `a0 = sp + 0x18`
  - `0x43a09c` delay slot 把 `a1 = v0`
  - 即 `strcpy(sp+0x18, v0)`
- 第二次拷贝:
  - `0x43a0c4` 取 `strcpy@plt`
  - `0x43a0c8` 设 `a0 = sp + 0x98`
  - `0x43a0cc` 设 `a1 = v0`
  - `0x43a0d0` 调用
  - 即 `strcpy(sp+0x98, v0)`

从栈布局可直接算出两个目的缓冲区大小都是 `0x80` 字节:

- `sp+0x18` 到 `sp+0x98` 相差 `0x80`
- `sp+0x98` 到保存寄存器的 `sp+0x118` 相差 `0x80`

### 4. 为什么它会溢出

- 对 `0x46c77c` 的静态查看显示，这里不是合法短字符串，而是大段连续的 `0xff`：
  - `0x46c77c`
  - `0x46c78c`
  - `0x46c79c`
  - `0x46c7ac`
  - 至少前 `0xc0` 字节全为 `0xff`
- 因此 `strcpy` 不会在 128 字节内遇到 `NUL` 终止符，必然越界覆盖 `sp+0x18` 或 `sp+0x98` 之后的栈内容。
- trace 中两次 `strcpy` 之后，程序还能继续跑到 `0x43a13c/0x43a154/0x43a16c`，符合“先栈破坏，后在后续控制流中崩溃”的模式。

## 关键证据

- `container.console.log`:
  - `PWD_answer1=Unknown`
  - `PWD_answer2=Unknown`
  - `SIGSEGV CAUGHT`
- 上述 `Unknown` 只能作为辅助证据，表明 `PWD_answer1/2` 缺失；真正决定性的证据仍然是 `0x43a074/0x43a0a8` 的 `nvram_get` 调用点和 `0x43a098/0x43a0d0` 的 `strcpy` 实参。
- `trace/usr_sbin_uhttpd.txt:710-720`:
  - `0x43a008` 进入答案校验函数
  - `0x43a090`、`0x43a0c4` 命中两个 `strcpy` callsite
- `trace/usr_sbin_uhttpd.txt:722-725`:
  - `0x43a13c`
  - `0x43a154`
  - `0x43a16c`
  - `SIGSEGV {si_addr=NULL}`

## 误报排除

- 不是误把 `body` 中的脚本名当 URL：
  - 第一包真实 URL 是 `/apply.cgi?Change_pvc_num`
  - 第二包真实 URL 是 `/debuginfo.htm`
  - 崩溃函数读取的是 `answer1/answer2`，因此对应第二包
- 不是“只有现象、没有 sink”：
  - `strcpy` 的真实调用点、目的栈地址、源寄存器值和缺失分支都已逐指令核验
- 不是“只有字符串命中、没有数据流”：
  - `answer1/answer2 -> s0/s1`
  - `PWD_answer1/2 -> nvram_get -> v0`
  - `v0==NULL -> 0x46c77c -> a1 -> strcpy(sp+0x18 / sp+0x98, a1)`
  - 该链条与 trace 的执行顺序一致

## 结论

- 本 case 不是误报，也不是证据不足。
- 真实漏洞在 `/usr/sbin/uhttpd` 的安全问题答案校验逻辑 `0x43a008`。
- 直接致崩 sink 是两个 `strcpy`：
  - `0x43a098`
  - `0x43a0d0`
- 触发条件是 `PWD_answer1/2` 在 NVRAM 中缺失，此时程序错误地把 `0x46c77c` 当作回退字符串复制到 128 字节栈缓冲区。
- 当前样本中，第二个请求 `GET /debuginfo.htm` 提供了进入该路径所需的 `answer1/answer2` 参数；第一包主要走语言修改路径，不是最终 sink。
