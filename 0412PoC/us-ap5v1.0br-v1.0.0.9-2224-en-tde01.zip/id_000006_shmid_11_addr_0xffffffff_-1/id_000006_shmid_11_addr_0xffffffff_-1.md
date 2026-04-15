# 第二轮分析: us-ap5v1.0br-v1.0.0.9-2224-en-tde01.zip_2 / id:000006,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- 漏洞二进制: `/bin/httpd`
- 漏洞类型: `空指针/非法指针解引用导致的拒绝服务`
- Source位置: `/bin/httpd` `websGetInput` `0x42aee8` 调用 `websUrlParse(0x41cd44)` 解析请求 URL；`0x41d11c-0x41d140` 把 `?` 后内容取为 query；随后 `0x42afbc-0x42afe4` 调用 `bstrdup(0x40778c)` 并写入 `wp+0xa4`
- Sink位置: `/bin/httpd` `websReadEvent` `0x42a1d4-0x42a1f0`，`$a0 = *(wp+0xa4)` 后调用 `strlen(0x47cbc0)`
- 一句话根因: `websReadEvent(state=8)` 在拼接 POST 参数前，无条件把 `wp+0xa4` 视为可用的 `QUERY_STRING` 字符串并调用 `strlen`；本次请求把 URL query `/main.html` 放入该字段后，程序在该 sink 处对失效的非空指针执行 `strlen` 并崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix=/` + `request.handler_name=/cgi-bin?/main.html` -> 原始 URL token `/cgi-bin?/main.html`
  - 原始 URL token 中 `?` 之后的 `/main.html` -> `websUrlParse` 在 `0x41d0ec-0x41d140` 切分 query -> 调用者局部变量 `72(s8)`
  - `72(s8)` -> `0x42afbc` 调 `bstrdup` -> `0x42afe4` 写入 `wp+0xa4`
  - POST body 整体参数串 -> `websReadEvent(state=8)` 当前输入缓冲 `44(s8)` -> 目标本应通过 `strlen(wp+0xa4)` + `brealloc(0x407854)` 追加到同一 `QUERY_STRING`；但在 `strlen` 前即崩溃，因此无法进入后续逐键分发
- 执行顺序:
  1. `trace/bin_httpd.txt:15` 命中 `/bin/httpd` `main=0x42fd60`
  2. `trace/bin_httpd.txt:744-820` 进入 `websReadEvent(state=1)`，读取请求行并调用 `websGetInput`
  3. `trace/bin_httpd.txt:850-896` 命中 `websUrlParse(0x41cd44)`，随后在 `0x42afbc-0x42afe4` 把 URL query 写入 `wp+0xa4`
  4. `trace/bin_httpd.txt:987-1062` 经过 `0x42b204` 继续解析 HTTP 头并转入 `state=8`
  5. `trace/bin_httpd.txt:1063-1070` 在 `0x42a1d4-0x42a1f0` 对 `wp+0xa4` 调用 `strlen`，随后 `0x42a1f8` 收到 `SIGSEGV`

## 与代表样本对比

- 当前结论独立于代表样本作出；本次没有读取兄弟 crash 目录。
- 与 README 中给出的代表样本元信息相比，本 case 与其共享相同二进制 `/bin/httpd` 和相同 sink `websReadEvent -> strlen(wp+0xa4)`。
- 本次重新分析补上的关键证据是 `wp+0xa4` 的真实字段含义：它不是 body 里的 `admin=/cgi-wzq`、`change=setWrlBaswzqnfo` 等键值，而是请求 URL `/cgi-bin?/main.html` 中 `?` 之后的 query `/main.html`，即 `QUERY_STRING`。

## 原始请求

- 方法来自 `VulPacket.json.packet_1.request.method`: `POST`
- 原始 URL 来自 `VulPacket.json.packet_1.request.prefix` 与 `handler_name`: `/` + `/cgi-bin?/main.html`
- 因此本次访问目标应理解为 `/cgi-bin?/main.html`
- 该 URL 的 `?` 前路径是 `/cgi-bin`，`?` 后 query 是 `/main.html`
- `body.admin=/cgi-wzq`、`body.change=setWrlBaswzqnfo` 等都只是 POST body 参数，不是原始 URL，也不是 `wp+0xa4` 的 source

## Trace映射

- 入口二进制: `/bin/httpd`
- `trace_summary.json` 已匹配 `main=0x42fd60` 到 `trace/bin_httpd.txt`
- 关键 trace:
  - `trace/bin_httpd.txt:15` -> `pc=0x42fd60`
  - `trace/bin_httpd.txt:739-744` -> `pc=0x429f30 ... 0x42a79c`
  - `trace/bin_httpd.txt:850-876` -> `pc=0x41cd44 ... 0x41ce78`，对应 `websUrlParse`
  - `trace/bin_httpd.txt:896-919` -> `pc=0x42af00 ... 0x42b194`，对应请求行解析结果写回 `wp`
  - `trace/bin_httpd.txt:987` -> `pc=0x42b204`
  - `trace/bin_httpd.txt:1063-1069` -> `pc=0x42a060 -> 0x42a074 -> 0x42a168 -> 0x42a198 -> 0x42a1b8 -> 0x42a1d4 -> 0x42a1f8`
  - `trace/bin_httpd.txt:1070` -> `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- 子进程链:
  - `trace/bin_httpd.txt:96-98` 的 `/bin/sh -c "echo 0 > /proc/sys/net/ipv4/tcp_timestamps"` 仅是环境初始化
  - `trace/14_tb_log.txt` 与 `trace/10_tb_log.txt` 未显示与崩溃直接相关的额外漏洞链

## Source -> Variable -> Sink 链条

### 1. Source: 请求 URL 的 query，而非 body 参数

- `websReadEvent(state=1)` 在 `0x42a090` 把读到的请求行缓冲传给 `0x42abe4`
- `0x42adcc` / `0x42ae50` 通过 `strtok(NULL, " \\t\\n")` 依次取出 method 之后的两个 token；第一个 token 即原始 URL `/cgi-bin?/main.html`
- `0x42aee8-0x42aef8` 调用 `websUrlParse(0x41cd44)` 解析该 URL
- 在 `websUrlParse` 内部:
  - `0x41d0ec-0x41d104` 查找 `'?'`
  - `0x41d11c` 把 `'?'` 改写为 `NUL`
  - `0x41d130-0x41d140` 令 query 指针指向 `'?'` 后一个字节，也就是 `/main.html`
- 调用约定可由 `websUrlParse` 的出参回写点确认:
  - `0x41d370-0x41d37c` 把 query 出参写到调用者传入的第 5 个指针槽
  - 在 `0x42aecc-0x42aed0`，该槽正是调用者栈上的 `72(s8)`

### 2. Variable: `wp+0xa4` 明确是 `QUERY_STRING`

- `0x42afbc-0x42afcc` 取 `72(s8)` 作为 `$a0`
- 该 `jalr` 的 GOT 槽位是 `0x4c6c54`，内容为 `0x0040778c`，即 `bstrdup`
- `0x42afe4` 将 `bstrdup(query)` 的返回值写入 `wp+0xa4`
- 字段含义可由 `websSetEnv` 反向验证:
  - `0x42ba9c` 读取 `wp+0xa4`
  - 该值在 `0x42baac-0x42bab4` 以键名 `QUERY_STRING` 写入环境
  - `.rodata 0x47ebb0` 处的字符串正是 `QUERY_STRING`

### 3. Sink: `strlen(*(wp+0xa4))`

- `websReadEvent(state=8)` 的路径由 `0x42a060 -> 0x42a074 -> 0x42a168` 选中
- `0x42a188-0x42a190` 先检查 `wp+0xa4 != NULL`
- `0x42a198-0x42a1b0` 再检查首字节非 `NUL`
- `0x42a1b8-0x42a1cc` 检查未设置 `0x2000` 标志
- `0x42a1d4-0x42a1e4` 将 `$a0 = *(wp+0xa4)`
- 该 `jalr` 的 GOT 槽位是 `0x4c6720`，内容为 `0x0047cbc0`，即 `strlen`
- `trace/bin_httpd.txt:1069-1070` 显示调用后立即在 `0x42a1f8` 收到 `SIGSEGV`

### 4. 崩溃前的预期后续动作

- 如果 `strlen` 成功，`0x42a240-0x42a24c` 会调用 `brealloc`
- 其 GOT 槽位 `0x4c694c` 内容为 `0x00407854`，即 `brealloc`
- 随后 `0x42a280-0x42a2c8` 会把 `'&'` 与当前 POST 数据缓冲追加到 `wp+0xa4`
- 这说明 `state=8` 的语义就是“已有 query 时，把 POST 参数并入同一参数串”

## 为什么判定为确认漏洞

- Source 已确认:
  - `wp+0xa4` 的 source 是 URL `/cgi-bin?/main.html` 中 `?` 之后的 query `/main.html`
  - 这由 `websUrlParse` 的分支和出参回写点直接给出
- Variable 已确认:
  - `0x42afbc` 调用的不是模糊 helper，而是 `bstrdup`
  - `0x42afe4` 明确把返回值写入 `wp+0xa4`
  - `websSetEnv` 又把同一字段作为 `QUERY_STRING` 导出
- Sink 已确认:
  - `0x42a1d4-0x42a1f0` 明确是 `strlen(*(wp+0xa4))`
  - trace 与 console 都证明这里就是实际崩溃点
- `source -> variable -> sink` 已闭环:
  - `request URL query /main.html`
  - `-> websUrlParse out-arg`
  - `-> bstrdup`
  - `-> wp+0xa4 / QUERY_STRING`
  - `-> websReadEvent(state=8) strlen(wp+0xa4)`
  - `-> SIGSEGV`
- 因而这不是“只有现象没有来源”的样本，也不是把 body 中看似路径的参数误认成 URL 的误报；它是一个真实可达的请求解析阶段拒绝服务漏洞。

## 仍未完全恢复但不影响确认的细节

- 当前仍不能从静态证据精确定位“`wp+0xa4` 为什么在到达 `strlen` 时变成坏指针”的更早内存破坏点。
- 但这不影响本 case 的漏洞确认，因为:
  - 真正参与 sink 的字段已经精确确认是 `QUERY_STRING`
  - sink 的 callsite、实参装载、GOT 目标函数和 trace 崩溃顺序都已核验
  - 崩溃发生在真实请求处理路径 `/bin/httpd` 内，而非环境初始化或无关子进程
- 若还要继续深挖更早的损坏点，需要额外的运行时内存快照或更细粒度的内存读写 trace，尤其是 `0x42afe4` 写入后的 `wp+0xa4` 实际值。
