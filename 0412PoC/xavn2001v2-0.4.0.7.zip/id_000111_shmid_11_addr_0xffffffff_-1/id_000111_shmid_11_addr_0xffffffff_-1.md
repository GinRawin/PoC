## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/lib/libnvram.so`
- 漏洞类型: 空指针解引用 / `NULL` 参数传入 `fputs`
- Source位置:
  - `/usr/sbin/uhttpd` `0x43a040` `cgi_value("answer1", ...)`，第一返回值在第二次 `jalr` 的 delay slot `0x43a064` 保存到 `s0`
  - `/usr/sbin/uhttpd` `0x43a060` `cgi_value("answer2", ...)`，第二返回值在 `0x43a070` 保存到 `s1`
- Sink位置:
  - `/usr/sbin/uhttpd` `0x43a17c` `nvram_set("last_error_ans2", s1)`
  - `/lib/libnvram.so` `write_key` 内 `0x1b44` `fputs(value, fp)`
- 一句话根因: `security_question` 失败路径没有检查 `cgi_value("answer2")` 的返回值，`answer2` 缺失时 `s1 == NULL`，随后被传给 `nvram_set("last_error_ans2", s1)`，库内 `write_key` 再执行 `fputs(NULL, fp)` 触发空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `packet_1.request.method=POST`, `packet_1.request.handler_name=apply.cgi?Change_pvc_num`, `packet_1.body.submit_flag=security_question` -> `cgi_setobject` 分发到 `security_question`
  - `packet_1.body.answer1=1` -> `cgi_value("answer1", ...)` 返回 `"1"`，保存到 `s0`
  - `packet_1.body.answer2` 缺失 -> `cgi_value("answer2", ...)` 返回 `NULL`，保存到 `s1`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 入口进程两次 `fork()` 后在子进程内继续处理请求。
  2. `cgi_setobject` 根据 `submit_flag=security_question` 命中分发表项 `security_question -> 0x43a008`。
  3. `0x43a008` 读取 `answer1` 和 `answer2`；trace 显示执行到 `0x43a0e0` 后直接落到 `0x43a13c`，说明 `s0 != NULL` 但 `s1 == NULL`。
  4. 失败分支依次执行 `nvram_set("enter_answer_again", "1")`、`nvram_set("last_error_ans1", s0)`、`nvram_set("last_error_ans2", s1)`。
  5. 第三个 `nvram_set` 把 `NULL` 传入 `/lib/libnvram.so:write_key` 的 `fputs(value, fp)`。
  6. trace 在 `0x43a16c` 后立刻出现 `SIGSEGV {si_addr=NULL}`，与 `fputs(NULL, fp)` 一致。

## 请求与入口

- 当前样本有两个 HTTP 包:
  - `packet_1`: `POST /apply.cgi?Change_pvc_num`
  - `packet_2`: `GET /AUTO_write_language.htm`
- 真实触发请求是 `packet_1`，不是 `packet_2`：
  - `packet_1.body.submit_flag=security_question`，而 `packet_2.body.submit_flag=reboot`
  - `uhttpd` 的分发表中 `0x471c8c` 明确是 `security_question -> 0x43a008`
  - trace 在 `trace/usr_sbin_uhttpd.txt:710` 命中 `0x43a008`，因此本次崩溃对应 `security_question` 路径，只能回到 `packet_1`
- `trace_summary.json` 将入口 `main=0x4047d4` 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- `trace/usr_sbin_uhttpd.txt:340-345` 显示 `11 -> 13 -> 15` 两次 `fork()`，期间没有 `execve()`，所以入口进程始终是 `/usr/sbin/uhttpd`
- 运行环境通过 `run.sh:5,8` 和 `run_debug.sh:6,9` 以 `LD_PRELOAD=libnvram-faker.so` 启动 `uhttpd`
- `/lib/libnvram.so` 与 `/lib/libnvram-faker.so` 的 `sha256` 完全相同，且 `cmp` 结果为 `0`，因此预加载库与固件库是字节级一致副本

## 执行流还原

1. `trace/usr_sbin_uhttpd.txt:690-709` 先进入 `cgi_setobject` 相关逻辑：
   - `0x40b95c` 初始化 `cgi_action`
   - `0x40b9a0` 查找 `submit_flag`
   - `0x40ba44 -> 0x40ba00 -> 0x40ba10` 在分发表里查找处理函数
2. 分发表 `0x471c8c` 的条目是：
   - 字符串: `security_question`
   - 处理函数: `0x43a008`
3. `trace/usr_sbin_uhttpd.txt:710-724` 命中：
   - `0x43a008`
   - `0x43a048`
   - `0x43a068`
   - `0x43a080`
   - `0x43a090`
   - `0x43a0a0`
   - `0x43a0b4`
   - `0x43a0c4`
   - `0x43a0d8`
   - `0x43a0e0`
   - `0x43a13c`
   - `0x43a154`
   - `0x43a16c`
   - 紧接 `SIGSEGV {si_addr=NULL}`
4. 这个顺序说明：
   - 两次 `cgi_value` 已经执行
   - 两次 `nvram_get + strcpy` 已经执行
   - 在判断阶段执行过 `beqz s0` 和 `beqz s1`
   - 之后直接进入失败路径的三个 `nvram_set`
   - 崩溃发生在第三个 `nvram_set` 之后，且 `si_addr=NULL` 明确指向空指针解引用

## Source -> Variable -> Sink

### 1. Source callsite 核验

- `0x43a030/0x43a038` 装载字符串 `0x45eb18`，内容是 `answer1`
- `0x43a03c` 设 `a1 = s0`，`0x43a040` 调用 `cgi_value`
- 第二次调用的 delay slot `0x43a064: move s0, v0` 把第一次 `cgi_value("answer1")` 的返回值保存到 `s0`
- `0x43a048/0x43a054` 装载字符串 `0x45eb24`，内容是 `answer2`
- `0x43a058` 设 `a2 = s1`，`0x43a060` 再次调用 `cgi_value`
- `0x43a070: move s1, v0` 把第二次 `cgi_value("answer2")` 的返回值保存到 `s1`

结论:

- `packet_1.body.answer1=1` 对应 `s0 = "1"`
- 当前 `packet_1` 根本没有 `answer2` 字段，因此 `cgi_value("answer2")` 最合理的结果是 `NULL`

### 2. `s1 == NULL` 的分支证据

- `0x43a0d8: beqz s0, 0x43a13c`
- `0x43a0e0: beqz s1, 0x43a13c`
- trace 顺序是 `0x43a0d8 -> 0x43a0e0 -> 0x43a13c`

这说明:

- 第一条分支没有直接跳走，因此 `s0 != NULL`
- 第二条分支后立刻落到 `0x43a13c`，因此 `s1 == NULL`
- 这与 `packet_1` 只有 `answer1`、没有 `answer2` 完全一致

### 3. 旧 `strcpy` 结论为什么不成立

- `0x43a074` 和 `0x43a0a8` 分别调用 `nvram_get("PWD_answer1")`、`nvram_get("PWD_answer2")`
- 若返回 `NULL`，分支会把 `v0` 置为 `0x45c77c`
- 该地址的实际内容以 `00 00 00 00` 开头，随后才是 HTML 片段，因此对 `strcpy` 来说它是空字符串
- `0x43a098` 和 `0x43a0d0` 的 `strcpy` 只会把空串复制到 `sp+0x18` 和 `sp+0x98`，不会形成旧报告声称的栈溢出
- `container.console.log:23-24` 的 `PWD_answer1=Unknown`、`PWD_answer2=Unknown` 也与库内 `read_key` 的 `fprintf(stderr, "%s=Unknown", key)` 逻辑一致，只能说明键缺失，不能证明 `strcpy` 有问题

### 4. 真实 sink 核验

- 失败路径三次 `nvram_set` 的 callsite:
  - `0x43a14c` / `0x43a150`: `nvram_set("enter_answer_again", "1")`
  - `0x43a164` / `0x43a168`: `nvram_set("last_error_ans1", s0)`
  - `0x43a17c` / `0x43a180`: `nvram_set("last_error_ans2", s1)`
- 第三个 callsite 的实参最关键:
  - `0x43a174: move a1, s1`
  - `0x43a178: lw t9, nvram_set`
  - `0x43a17c: jalr t9`
  - delay slot `0x43a180: addiu a0, a0, -0x14b0`，得到键名 `last_error_ans2`
- `/lib/libnvram.so:nvram_set` 只是薄包装，随后进入 `write_key`
- `write_key` 的真实危险点在:
  - `0x1b34: lw a1, 0x20(fp)` 取 `FILE *`
  - `0x1b38: lw a0, 0x334(fp)` 取 value 指针
  - `0x1b44: jalr t9` 调 `fputs`
- 当 `a0 == NULL` 时，`fputs(NULL, fp)` 会直接导致空指针崩溃

结论:

- 真实 sink 不是 `uhttpd` 里的两个 `strcpy`
- 真实 sink 是 `uhttpd` 把 `s1 == NULL` 传进 `nvram_set("last_error_ans2", s1)`，再由 `/lib/libnvram.so:write_key` 在 `0x1b44` 调用 `fputs(NULL, fp)`

## 关键证据

- `VulPacket.json:15-20`
  - `submit_flag=security_question`
  - `answer1=1`
  - 没有 `answer2`
- `VulPacket.json:38-38`
  - `packet_2.body.submit_flag=reboot`
- `trace/usr_sbin_uhttpd.txt:710-724`
  - 命中 `0x43a008` 的 `security_question` 路径
  - 命中 `0x43a0d8 -> 0x43a0e0 -> 0x43a13c`
  - 命中第三个失败分支 `nvram_set` 前的 `0x43a16c`
- `trace/usr_sbin_uhttpd.txt:725`
  - `SIGSEGV {si_addr=NULL}`
- `container.console.log:23-26`
  - `PWD_answer1=Unknown`
  - `PWD_answer2=Unknown`
  - `SIGSEGV CAUGHT`
- `run.sh:5,8` 与 `run_debug.sh:6,9`
  - 运行时显式设置 `LD_PRELOAD=libnvram-faker.so`
- `sha256sum` 与 `cmp`
  - `libnvram.so` 和 `libnvram-faker.so` 字节完全一致

## 误报排除

- 不是 `packet_2` 触发:
  - `packet_2` 的 `submit_flag` 是 `reboot`
  - 但当前 trace 明确进入 `security_question -> 0x43a008`
  - 因此真实触发请求只能是 `packet_1`
- 不是旧报告里的 `strcpy` 栈溢出:
  - 回退地址应为 `0x45c77c`，不是旧报告写的 `0x46c77c`
  - `0x45c77c` 首字节就是 `NUL`，`strcpy` 复制的是空串
  - 旧结论缺少对 `lui/addiu` 实际地址和内存内容的核验
- 不是只有现象没有链条:
  - 已核实 `packet_1.body.answer1 -> s0`
  - 已核实 `packet_1` 缺失 `answer2 -> s1 == NULL`
  - 已核实 `s1 == NULL -> nvram_set("last_error_ans2", s1) -> write_key -> fputs(NULL, fp)`
  - 该链条与 trace 的执行顺序和 `si_addr=NULL` 完全一致

## 结论

- 当前 case 不是误报，也不是证据不足
- 真实触发请求是 `packet_1: POST /apply.cgi?Change_pvc_num`
- 真实业务路径是 `submit_flag=security_question`
- 真实崩溃二进制是 `/lib/libnvram.so`：
  - 入口和调用者是 `/usr/sbin/uhttpd`
  - 运行时实际加载的是字节相同的 `/lib/libnvram-faker.so`
- 根因是 `uhttpd` 在 `answer2` 缺失时把 `NULL` 继续传给 `nvram_set("last_error_ans2", s1)`，而 `libnvram.so` 的 `write_key` 没有做空值校验，最终在 `0x1b44` 调用 `fputs(NULL, fp)` 触发 `SIGSEGV`
