# 漏洞分析: xwn5001-0.4.1.1.zip / id:000008,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `0x43a008` `0x43a164`
- Source位置: `/usr/sbin/uhttpd` `0x43a008` `0x43a040`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `submit_flag=security_question` 进入安全问题 handler `0x43a008` 后，程序读取 `PWD_answer1/PWD_answer2` 但不检查返回值是否为空；当请求缺失这两个字段时，错误分支仍把 `NULL` 作为 value 传给 `nvram_set`，最终在 `0x43a154` 之后触发 `SIGSEGV(NULL)`。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`，`request.prefix=/`，`request.handler_name=apply.cgi?Change_pvc_num` -> 原始请求 URL `/apply.cgi?Change_pvc_num`
  - `packet_1.body.submit_flag="security_question"` -> `sym.cgi_setobject` 中 `cgi_value("submit_flag") @ 0x40b9ac` -> 分发表项 `0x471cac` -> handler `0x43a008`
  - `packet_1.body.PWD_answer1` 缺失 -> `cgi_value("PWD_answer1") @ 0x43a040` 返回 `NULL` -> 保存到 `s0`
  - `packet_1.body.PWD_answer2` 缺失 -> `cgi_value("PWD_answer2") @ 0x43a060` 返回 `NULL` -> 保存到 `s1`
  - `s0(NULL)` -> `nvram_set("last_error_ans1", s0)` 的 value 参数，调用点 `0x43a164`
  - `s1(NULL)` 原本还会继续流向 `nvram_set("last_error_ans2", s1)`，但程序先在前一个空 value 路径上崩溃
- 执行顺序:
  1. `uhttpd` 处理 `packet_1` 的 `POST /apply.cgi?Change_pvc_num`
  2. `0x406c28 -> 0x406eb0 -> sym.cgi_setobject(0x40b95c)` 解析 POST body
  3. `0x40b9ac` 读取 `submit_flag`，命中 `"security_question"` 表项 `0x471cac`，跳到 `0x43a008`
  4. `0x43a040` 和 `0x43a060` 依次读取 `PWD_answer1`、`PWD_answer2`，两者都因字段缺失而返回 `NULL`
  5. handler 进入错误分支，在 `0x43a14c` 先执行 `nvram_set("enter_answer_again","1")`，然后在 `0x43a164` 准备执行 `nvram_set("last_error_ans1", NULL)`，随即出现 `SIGSEGV(NULL)`

## 原始请求

这个样本有两个 packet，但真正触发崩溃的是 `packet_1`:

- 方法: `POST`
- URL: `/apply.cgi?Change_pvc_num`
- 依据: `packet_1.request.prefix="/"` 与 `packet_1.request.handler_name="apply.cgi?Change_pvc_num"`
- 关键 body:
  - `submit_flag=security_question`
  - 存在 `answer2`
  - 不存在 `PWD_answer1`
  - 不存在 `PWD_answer2`

`packet_2` 是后续的 `GET /PLC_scan_result.htm`，但本次 trace 已在 `packet_1` 的 `security_question` handler 内崩溃，因此 `packet_2` 不是触发源。

## 入口二进制与 Trace 映射

- 固件入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 已恢复 `main=0x4047d4`
- `trace_summary.json` 将入口 trace 命名为 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 片段:
  - `usr_sbin_uhttpd.txt:646` `pc=0x406c28`
  - `usr_sbin_uhttpd.txt:670` `pc=0x40b95c`
  - `usr_sbin_uhttpd.txt` 随后出现 `0x40ba44 -> 0x40ba10 -> 0x43a008`
  - `usr_sbin_uhttpd.txt` 继续执行到 `0x43a048 -> 0x43a068 -> 0x43a080 -> 0x43a0b4 -> 0x43a13c -> 0x43a154`
  - `usr_sbin_uhttpd.txt:703` `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

没有子进程 `fork/execve` 参与漏洞触发；问题发生在 `uhttpd` 进程内部。

## 关键静态证据

### 1. `submit_flag=security_question` 确实映射到 `0x43a008`

手工解码 `cgi_setobject` 分发表 `0x471c64` 附近:

- `0x471ca0 -> { "match_sn", 0x0, 0x43a1b0 }`
- `0x471cac -> { "security_question", 0x0, 0x43a008 }`
- `0x471cb8 -> { "ping", 0x3a, 0x40abfc }`
- `0x471cc4 -> { "Change_pvc_num", 0x0, 0x40b590 }`

所以这里虽然原始 URL 是 `/apply.cgi?Change_pvc_num`，真正决定业务分支的是 body 里的 `submit_flag=security_question`。

### 2. `0x43a008` 先读 `PWD_answer1/PWD_answer2`，后面直接把它们传给 `nvram_set`

`0x43a008` 附近反汇编可解释为:

- `0x43a040`: `cgi_value("PWD_answer1", req, ...)`
- `0x43a060`: `cgi_value("PWD_answer2", req, ...)`
- `0x43a078`: `nvram_get("PWD_answer1")`
- `0x43a090`: `strcpy(sp+0x18, old_pwd_answer1_or_default)`
- `0x43a0a8`: `nvram_get("PWD_answer2")`
- `0x43a0c4`: `strcpy(sp+0x98, old_pwd_answer2_or_default)`
- `0x43a0d8`: `if (s0 == NULL) goto 0x43a13c`
- `0x43a0e0`: `if (s1 == NULL) goto 0x43a13c`
- `0x43a14c`: `nvram_set("enter_answer_again", "1")`
- `0x43a164`: `nvram_set("last_error_ans1", s0)`
- `0x43a17c`: `nvram_set("last_error_ans2", s1)`

对应字符串:

- `0x45eae0 -> "PWD_answer1"`
- `0x45eaec -> "PWD_answer2"`
- `0x45eaf8 -> "enter_answer_again"`
- `0x45eb0c -> "last_error_ans1"`
- `0x45eb1c -> "last_error_ans2"`

## Source -> Variable -> Sink 数据流

当前样本的关键数据流是:

1. `packet_1.body.submit_flag="security_question"` 被 `0x40b9ac` 读取，用于选择 handler `0x43a008`
2. `packet_1.body.PWD_answer1` 在 `0x43a040` 被读取，但字段缺失，返回 `NULL`
3. 这个返回值通过第二次 `cgi_value` 调用的 delay slot 保存到 `s0`
4. `packet_1.body.PWD_answer2` 在 `0x43a060` 被读取，同样缺失，返回 `NULL`
5. 该值保存到 `s1`
6. 程序命中错误分支 `0x43a13c`
7. `0x43a164` 处继续用 `s0` 作为 `nvram_set("last_error_ans1", s0)` 的 value 参数
8. 由于 `s0 == NULL`，后续 `nvram_set` 内部解引用空指针，trace 在 `0x43a154` 后报 `SIGSEGV(NULL)`

这是标准的“缺参 -> 空指针未校验 -> 危险调用”链条。

## Console / Trace 佐证

`container.console.log` 中有:

- `PWD_answer1=Unknown`
- `PWD_answer2=Unknown`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`

这与 `nvram_get("PWD_answer1") / nvram_get("PWD_answer2")` 在字段缺失时走默认/Unknown 路径的静态逻辑完全一致，也进一步说明崩溃点就在安全问题校验分支内部。

## 结论

这不是证据不足，而是可确认的参数校验缺失漏洞。

确认依据有四条:

1. `packet_1` 的 `submit_flag=security_question` 到 handler `0x43a008` 的映射可以精确恢复
2. 真实 source 已定位为 `cgi_value("PWD_answer1") @ 0x43a040` 和 `cgi_value("PWD_answer2") @ 0x43a060`
3. 真实 sink 已定位为错误分支中的 `nvram_set("last_error_ans1", s0)` 调用点 `0x43a164`
4. trace 的 `SIGSEGV(NULL)` 与“把缺失字段返回的 NULL 继续传给 nvram_set”完全吻合

根因不是 body 中那些超长 `ether_*` / `wan_*` 字段，而是:

- 请求用 `submit_flag=security_question` 进入安全问题校验逻辑
- 但没有提供 handler 所要求的 `PWD_answer1/PWD_answer2`
- 程序没有在错误分支里验证这两个指针是否为空
- 继续把 `NULL` 作为 NVRAM value 传入写入函数，最终崩溃

