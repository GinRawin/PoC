## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / 拒绝服务
- Source位置: `0x43a040`，`cgi_value("PWD_answer1", body_kv, kv_count)`；次要 source 为 `0x43a060` 的 `cgi_value("PWD_answer2", ...)`
- Sink位置: `0x43a164`，`jalr -> nvram_set("last_error_ans1", $16)`；trace 记录的最后一个基本块起点为 `0x43a154`
- 一句话根因: `submit_flag=security_question` 会分发到 `0x43a008`，该处理函数在 `PWD_answer1` 缺失时把 `$16` 置为 `NULL`，但错误分支仍把 `$16` 作为第二实参传给 `nvram_set("last_error_ans1", ...)`，从而触发空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.handler_name=apply.cgi?Change_pvc_num` -> 原始请求 URL 为 `/apply.cgi?Change_pvc_num`
  - `body.submit_flag=security_question` -> `cgi_setobject` 在 `0x40b9ac` 读出 `submit_flag`，并通过分发表 `0x471c8c` 命中 `"security_question" -> 0x43a008`
  - `body.PWD_answer1` 缺失 -> `0x43a040` 的 `cgi_value("PWD_answer1", ...)` 返回 `NULL`，写入 `$16`
  - `body.PWD_answer2` 缺失 -> `0x43a060` 的 `cgi_value("PWD_answer2", ...)` 返回 `NULL`，写入 `$17`
  - `nvram_get("PWD_answer1")` / `nvram_get("PWD_answer2")` 若为空会被替换成 `"Unknown"` 拷到栈上，仅用于后续比较；它们不是本次崩溃 source
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi?Change_pvc_num`。
  2. `0x40b9ac` 调用 `cgi_value("submit_flag", ...)` 取到 `security_question`。
  3. `0x471c8c` 表项把该 `submit_flag` 分发到处理函数 `0x43a008`。
  4. `0x43a040` 取 `PWD_answer1` 失败，`$16=NULL`；`0x43a060` 取 `PWD_answer2` 失败，`$17=NULL`。
  5. `0x43a0d8` 发现 `$16==NULL`，直接跳入错误分支 `0x43a13c`。
  6. `0x43a164` 调用 `nvram_set("last_error_ans1", $16)`，第二实参为 `NULL`。
  7. trace 在 `trace/usr_sbin_uhttpd.txt` 记录 `pc=0x43a13c -> pc=0x43a154 -> SIGSEGV {si_addr=NULL}`，与该 sink 基本块一致。

## 请求与入口

- 当前 case 目录内未提供 `analysis_report_template.md`；本报告沿用现有报告的章节顺序重写，但结论和证据全部基于本次独立分析。
- 原始请求以 `VulPacket.json` 的 `packet_1.request` 为准:
  - 方法: `POST`
  - URL: `/apply.cgi?Change_pvc_num`
  - header: `HOST=192.168.0.50`, `Cookie=uid=xhyxhy`
  - body: `submit_flag=security_question`, `hidden_lang_avi=1`, `New_Language=...`, `lang_in_flash=...`, `answer2=1`
- `packet_1.body` 中并不存在 `PWD_answer1` 或 `PWD_answer2`；不要把 `packet_2.body` 中的同名键误认为本次崩溃请求的 source。真正选择处理路径的是 `packet_1.body.submit_flag=security_question`。
- 入口进程是 `/usr/sbin/uhttpd`，`main=0x4047d4`，`trace_summary.json` 已把入口 trace 匹配到 `trace/usr_sbin_uhttpd.txt`。
- `trace/usr_sbin_uhttpd.txt` 中只有早期 `fork()` 子进程，相关 `9_tb_log.txt` 最终 `exit(0)`；崩溃仍发生在 `uhttpd` 主进程自身。

## Source 到 Sink 链条

### 1. `submit_flag` 选中 `security_question` 处理函数

- `0x40b9a0` 到 `0x40b9b0`:
  - `$4 = 0x45dd34 ("submit_flag")`
  - `$5 = $18`, `$6 = $19`
  - `jal 0x40b4a4` 调用 `cgi_value("submit_flag", $18, $19)`
- 返回值保存在 `$17`，随后 `0x40ba44` 到 `0x40ba54` 遍历 `0x471890` 开始的分发表。
- 分发表中 `0x471c8c` 的三元组为:
  - 字符串指针 `0x44e4f4 -> "security_question"`
  - 索引 `0x00000000`
  - 处理函数 `0x43a008`
- 因此本次执行确实是 `packet_1.body.submit_flag=security_question` 进入 `0x43a008`，不是 `packet_2` 的 `debuginfo.htm` 路径。

### 2. 真实 source: 读取缺失的 `PWD_answer1` / `PWD_answer2`

- `0x43a028` 到 `0x43a044`:
  - `$16 <- $4`, `$17 <- $5` 保存上层传入的 CGI 键值数组和数量
  - `$4 = 0x45eb14 ("PWD_answer1")`
  - `$5 = $16`, `$6 = $17`
  - `jalr 0x44b4a4` 对应本地函数 `cgi_value`
- `0x43a064` 把返回值写回 `$16`。由于 `packet_1.body` 没有 `PWD_answer1`，这里的结果只能是 `NULL`。
- `0x43a048` 到 `0x43a064` 紧接着同样执行:
  - `$4 = 0x45eb20 ("PWD_answer2")`
  - `cgi_value("PWD_answer2", ...)`
  - 返回值写入 `$17`
- 因为 `packet_1.body` 也没有 `PWD_answer2`，`$17` 同样为 `NULL`。

### 3. 中间变量与分支条件

- `0x43a068` 到 `0x43a0d0`:
  - `nvram_get("PWD_answer1")` / `nvram_get("PWD_answer2")`
  - 若返回空，则回退到常量 `"Unknown"`
  - 再分别 `strcpy` 到栈缓冲区 `sp+0x18` 和 `sp+0x98`
- `container.console.log` 中的
  - `PWD_answer1=Unknown`
  - `PWD_answer2=Unknown`
  说明设备当前配置里这两个 NVRAM 键本身就是空，和上面的回退逻辑一致。
- 关键分支在 `0x43a0d8` 与 `0x43a0e0`:
  - `beqz $16, 0x43a13c`
  - `beqz $17, 0x43a13c`
- 也就是说，代码已经知道用户提交的答案可能为空，但错误分支并没有停止使用空指针。

### 4. 真实 sink: `nvram_set("last_error_ans1", NULL)`

- 错误分支从 `0x43a13c` 开始。
- `0x43a154` 到 `0x43a168` 这一基本块里:
  - `$4 = 0x45eb40 ("last_error_ans1")`
  - `move $5, $16`
  - `jalr 0x44b310`
- 通过 GOT 可知 `0x44b310` 是导入函数 `nvram_set`。
- 因为前面 `0x43a0d8` 已经证明 `$16==NULL`，所以该调用的真实实参就是:
  - `nvram_set("last_error_ans1", NULL)`
- 这就是本次崩溃的 sink。`trace/usr_sbin_uhttpd.txt` 的最后两条是:
  - `pc=0x43a13c`
  - `pc=0x43a154`
  - 随后 `SIGSEGV {si_addr=NULL}`
- trace 记录的是基本块起始地址，因此最后看到 `0x43a154` 而不是 `0x43a164`；两者在同一条错误路径上，不矛盾。

## 关键证据

- 请求证据:
  - `VulPacket.json` 的 `packet_1.request` 明确是 `POST /apply.cgi?Change_pvc_num`
  - `packet_1.body.submit_flag=security_question`
  - `packet_1.body` 不含 `PWD_answer1`、`PWD_answer2`
- 分发证据:
  - `0x40b9ac`: `cgi_value("submit_flag", ...)`
  - `0x471c8c`: `"security_question" -> 0x43a008`
- source 证据:
  - `0x43a040`: `cgi_value("PWD_answer1", ...)`
  - `0x43a060`: `cgi_value("PWD_answer2", ...)`
  - 缺失对应 body 键时，返回 `NULL`
- sink 证据:
  - `0x43a0d8`: `beqz $16, 0x43a13c`
  - `0x43a164`: `jalr -> nvram_set`
  - 调用前 `move $5, $16`，而 `$16==NULL`
- trace / console 证据:
  - `trace/usr_sbin_uhttpd.txt:721`: `pc=0x43a13c`
  - `trace/usr_sbin_uhttpd.txt:722`: `pc=0x43a154`
  - `trace/usr_sbin_uhttpd.txt:723`: `SIGSEGV {si_addr=NULL}`
  - `container.console.log`: `PWD_answer1=Unknown`, `PWD_answer2=Unknown`, `SIGSEGV CAUGHT`

## 结论与边界

- 这是可闭环的真实漏洞，不是误报。
- 漏洞成立所需的四条关键链条已经齐全:
  - 可解释的 source: `cgi_value("PWD_answer1")` / `cgi_value("PWD_answer2")`
  - 可解释的中间变量: `$16/$17`
  - 可解释的 sink: `nvram_set("last_error_ans1", $16)`
  - 与 trace / console / 反汇编一致的证据闭环
- 最小触发条件不是提交恶意长字符串，而是让 `security_question` 路径在缺失 `PWD_answer1` 时继续走到错误分支。
- `packet_2` 里的 `PWD_answer1/PWD_answer2` 不影响本次判定；崩溃点已经由 `packet_1` 的 `submit_flag=security_question` 路径闭合。
