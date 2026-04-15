# 漏洞分析: us-ap5v1.0br-v1.0.0.9-2224-en-tde01.zip / id:000000,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- 漏洞二进制: `/bin/httpd`
- 漏洞类型: `空指针解引用`
- Source位置:
  - `/bin/httpd` `websGetInput` `0x42a7c8-0x42a7e4`: 调用开始先把输出指针 `*arg_1` 清零
  - `/bin/httpd` `parse_reqline(0x42abe4)` `0x42af6c-0x42afb4`: 对 URL token 做 `strstr(...,"cgi-bin")`，命中后置位 `wp->flags |= 0x4000`
  - `/bin/httpd` `parse_headers(0x42b204)` `0x42b8b4-0x42b938`: 解析 `Content-Length`，把 `atoi(value)` 写入 `wp+0xe0`，并置位 `wp->flags |= 0x400`
- Sink位置: `/bin/httpd` `websReadEvent` `0x42a214-0x42a220`，调用 `strlen(var_2c)`，其中 `a0 == NULL`
- 一句话根因: 该 HTTP 状态机在 `POST + cgi-bin + Content-Length>0` 的组合下，会在“请求头结束”的同一次迭代里直接切到 `state=8`，但这条路径没有重新填充新的 body 指针，导致局部变量 `var_2c` 仍为 `NULL`，随后被 `strlen` 解引用崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` -> `parse_reqline` `0x42acc0-0x42ad0c` -> `wp->flags |= 0x20`
  - `request.handler_name=/webroot?/cgi-bin` -> URL token 含 `"cgi-bin"` -> `0x42af6c-0x42afb4` -> `wp->flags |= 0x4000`
  - `header.Content-Length=13` -> `0x42b8b4-0x42b938` -> `wp->field_0xe0 = 13`, `wp->flags |= 0x400`
  - 头结束空行 -> `websGetInput` 在本轮未执行输出赋值 `0x42aba0`，因此调用者局部 `var_2c` 维持为初始化时的 `NULL`
- 执行顺序:
  1. `trace/bin_httpd.txt:744-822` 进入 `/bin/httpd` 的 `websGetInput`，先解析 request line。
  2. `trace/bin_httpd.txt:830-957` 进入 `parse_reqline(0x42abe4)`，把 `POST` 和 `cgi-bin` 两个条件写进 `wp->flags`。
  3. `trace/bin_httpd.txt:987-1063` 进入 `parse_headers(0x42b204)`，解析 `Content-Length` 并在头结束后返回。
  4. `trace/bin_httpd.txt:1064-1069` 回到 `websGetInput`，因为 `POST + cgi-bin + Content-Length>0`，直接把 `wp->state` 改成 `8` 并返回，但没有填充新的 `var_2c`。
  5. `trace/bin_httpd.txt:1070-1077` 回到 `websReadEvent` 的 `state=8` 分支，块 `0x42a1f8` 中最终执行 `strlen(NULL)` 并收到 `SIGSEGV`。

## 原始请求

- 方法来自 `VulPacket.json.packet_1.request.method`: `POST`
- 请求目标以 `handler_name` 为准，应理解为 `/webroot?/cgi-bin`
- `body.change=setWrlBasicInfo` 和其他 body 字段只是请求参数，不是原始 URL
- `header.Content-Length=13` 与 `VulPacket.json` 展示出的 body 键值数量明显不一致；本次崩溃不需要进入业务 handler，仅靠 request line、header 结束和状态机切换就能闭环

## Trace映射

- 入口二进制: `/bin/httpd`
- Main地址: `0x42fd60`
- 命中的入口 trace: `trace/bin_httpd.txt`
- 子进程 trace 链:
  - `trace/bin_httpd.txt:96-98` 只显示环境初始化噪声: `fork()` 出 pid 14，再 `execve("/bin/sh", {"sh","-c","echo 0 > /proc/sys/net/ipv4/tcp_timestamps",NULL})`
  - `trace/14_tb_log.txt:729` 该 `/bin/sh` 子进程 `exit(1)`，不是漏洞路径
- 真正崩溃路径全部留在 `trace/bin_httpd.txt`
- 关键 trace 位置:
  - `trace/bin_httpd.txt:739-744` -> `websReadEvent(0x429f30)` 调 `websGetInput(0x42a79c)`
  - `trace/bin_httpd.txt:830-957` -> `parse_reqline(0x42abe4)`
  - `trace/bin_httpd.txt:987-1063` -> `parse_headers(0x42b204)`
  - `trace/bin_httpd.txt:1064-1069` -> `0x42aac4 -> 0x42aae4 -> 0x42ab00 -> 0x42ab3c -> 0x42ab68 -> 0x42abc8`
  - `trace/bin_httpd.txt:1070-1076` -> `0x42a060 -> 0x42a074 -> 0x42a168 -> 0x42a198 -> 0x42a1b8 -> 0x42a1d4 -> 0x42a1f8`
  - `trace/bin_httpd.txt:1077` -> `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键地址与数据流

### 1. `websGetInput` 的输出指针在进入函数时被清零

- `0x42a7c8` 把局部 `var_2c` 置 0
- `0x42a7d0-0x42a7d8` 立刻把 `*arg_1 = 0`
- `0x42a7dc-0x42a7e4` 同样把长度输出 `*arg_2 = 0`
- 因此，如果后续状态分支没有走到唯一的结果回填点 `0x42aba0-0x42abbc`，调用者看到的 `var_2c` 就仍然是 `NULL`

### 2. request line 把 `POST` 和 `cgi-bin` 写进状态标志

- `parse_reqline` 从请求行里用 `strtok(..., " \t")` 取出方法 token
- `0x42acc0-0x42ad0c` 对 `"POST"` 比较成功后，执行 `wp->flags |= 0x20`
- 同一函数在 `0x42af6c-0x42afb4` 上对 URL token 做 `strstr(url, "cgi-bin")`
- 本次 trace 经过 `0x42af98`，说明该比较成功，随后执行 `wp->flags |= 0x4000`
- 这与 `VulPacket.json` 中 `request.handler_name=/webroot?/cgi-bin` 一致

### 3. `Content-Length` 触发 `state=8`

- `parse_headers(0x42b204)` 会循环处理每一条 header
- `0x42b888-0x42b8a8` 命中 `"content-length"`
- `0x42b8b4-0x42b8d8` 调 `atoi` 解析 header 值，并把结果写入 `wp+0xe0`
- `0x42b8ec-0x42b910` 在值大于 0 时置位 `wp->flags |= 0x400`
- 头解析返回后，`websGetInput` 在 `0x42aaac-0x42ab20` 检查到:
  - `wp->flags & 0x20` 为真，说明是 `POST`
  - `wp->flags & 0x400` 为真，说明 `Content-Length > 0`
  - 因此执行 `wp->state = 8`
- 随后的 `0x42ab3c-0x42ab68` 又因为 `wp->flags & 0x4000` 为真，直接返回 `1`，没有先做下一次读取

### 4. 头结束路径跳过了唯一的输出赋值点，所以 `var_2c` 仍为 `NULL`

- `0x42aba0-0x42abbc` 是本函数把 `local_2c/local_28` 回填给调用者的唯一路径
- 本次 trace 在 header 结束后走的是:
  - `0x42aac4 -> 0x42aae4 -> 0x42ab00 -> 0x42ab3c -> 0x42ab68 -> 0x42abc8`
- 该路径明确跳过了 `0x42aba0`
- 所以回到 `websReadEvent` 时，调用者栈上的 `[fp+0x2c]` 仍是最初的 `NULL`

### 5. 真正的 sink 是 `strlen(var_2c)`，不是前一个 `strlen(wp->field_0xa4)`

- `state=8` 分支起点是 `0x42a168`
- trace 依次命中 `0x42a168 -> 0x42a198 -> 0x42a1b8 -> 0x42a1d4 -> 0x42a1f8`
- `0x42a1d4-0x42a1f0` 的确先对 `wp->field_0xa4` 调了一次 `strlen`
- 但 `0x42a1f8` 已经是该调用返回后的下一块起点；这说明第一个 `strlen(wp->field_0xa4)` 已经返回
- 从 `0x42a1f8` 开始的下一段指令会做:
  - `0x42a20c`: 取 `var_2c`
  - `0x42a214`: `move a0, var_2c`
  - `0x42a220`: 调 `strlen(a0)`
- 因为上一步已经证明 `var_2c == NULL`，这里的真实 sink 是 `strlen(NULL)`
- `trace/bin_httpd.txt:1077` 的 `si_addr=NULL` 与这个 callsite 完全一致

### 6. `request.handler_name` 仍然会进入 `wp->field_0xa4`，但那不是本次崩溃的空指针参数

- `websUrlParse(0x41cd44)` 在 `0x41d0ec-0x41d158` 按 `'?'` 分割 URL
- 指向 `'?'` 后子串的局部 `local_44` 会在函数末尾 `0x41d360-0x41d37c` 通过第 6 个输出参数返回
- `parse_reqline` 调用 `websUrlParse` 时，第 6 个输出参数正是调用者局部 `local_72`
- `0x42afb8-0x42afe4` 随后执行 `bstrdup(local_72)`，把它写入 `wp+0xa4`
- `websSetEnv(0x42ba68)` 又在 `0x42ba94-0x42bab8` 把同一字段作为 `QUERY_STRING`
- 也就是说，旧报告把 `wp+0xa4` 的来源看成未知是错误的；它确实来自 request line 中 `'?'` 后的 `/cgi-bin`
- 但本次真正导致 `SIGSEGV` 的空指针参数不是 `wp+0xa4`，而是未填充的 `var_2c`

## 为什么不是 `setWrlBasicInfo` 业务漏洞

- `VulPacket.json.body.change=setWrlBasicInfo` 只是请求参数
- 本次 trace 没有命中 `sym.formWifiBasicSet (0x44e1f8)`，也没有进入该 handler 内部的 `websGetVar("broadcastSsid")` 等路径
- 崩溃发生在 HTTP 头结束后、业务 handler 分发前的公共解析状态机中
- 因此这不是 `setWrlBasicInfo` 的业务逻辑漏洞，而是 `/bin/httpd` 自身的请求解析空指针解引用

## 误报检查

- 为什么不是误报:
  - 崩溃发生在真实入口进程 `/bin/httpd`，而不是 `/bin/sh` 噪声子进程
  - trace 能把关键控制流闭环到具体 callsite: `websGetInput` 初始化输出为 `NULL` -> header 结束路径跳过回填 -> `websReadEvent` `strlen(NULL)`
  - `container.console.log` 最终记录了 `SIGSEGV`
- 为什么可以升级为 `确认漏洞`:
  - source 已可解释: `POST`、`cgi-bin`、`Content-Length` 三个请求字段共同驱动状态机进入错误分支
  - variable 已可解释: 调用者局部 `var_2c` 因跳过 `0x42aba0` 仍为 `NULL`
  - sink 已可解释: `0x42a214-0x42a220` 把这个 `NULL` 直接作为 `strlen` 参数
  - 关键 trace、callsite 和寄存器装载彼此一致，没有依赖旧报告或模糊字符串猜测

## 证据

- 关键 trace:
  - `trace/bin_httpd.txt:744-822` 命中 `websGetInput`
  - `trace/bin_httpd.txt:830-957` 命中 `parse_reqline(0x42abe4)`
  - `trace/bin_httpd.txt:987-1063` 命中 `parse_headers(0x42b204)`
  - `trace/bin_httpd.txt:1064-1069` 命中 `0x42aac4/0x42aae4/0x42ab00/0x42ab3c/0x42ab68/0x42abc8`
  - `trace/bin_httpd.txt:1070-1077` 命中 `state=8` 入口并最终 `SIGSEGV`
- 关键反汇编:
  - `0x42a7c8-0x42a7e4`: `websGetInput` 初始化输出为 `NULL`
  - `0x42aba0-0x42abbc`: 唯一的输出回填点
  - `0x42acc0-0x42ad0c`: `POST` -> `wp->flags |= 0x20`
  - `0x42af6c-0x42afb4`: `strstr(url,"cgi-bin")` -> `wp->flags |= 0x4000`
  - `0x42b8b4-0x42b938`: `Content-Length` -> `wp->field_0xe0` / `wp->flags |= 0x400`
  - `0x42aaac-0x42ab20`: `POST + Content-Length>0` -> `wp->state = 8`
  - `0x42a214-0x42a220`: `move a0, var_2c` 后调用 `strlen`
- 关键辅助日志:
  - `container.console.log` 中 `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log` 中 `Segmentation fault (core dumped)`
