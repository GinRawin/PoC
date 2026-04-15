## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` 函数 `fcn.00430780@0x430780` 内 `strcpy@0x430860`
- Source位置: `/usr/sbin/uhttpd` 函数 `0x43138c` 内 `cgi_value("qos_mac_priority")@0x4313c4`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `plc_qos_mac_add` 后续 PLC 规则解析函数把用户可控的第一个 token 复制到 `sp+0x30`，而该局部区到下一个缓冲 `sp+0x40` 只有 16 字节；32 字节 `qos_mac_priority` 先破坏相邻局部变量，再在第二次解析时演化为 `strcpy(..., NULL)` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/"` + `request.handler_name="apply.cgi?upgrade_check_free.cgi"` -> 原始请求 URL `/apply.cgi?upgrade_check_free.cgi`
  - `body.submit_flag="plc_qos_mac_add"` -> 进入 PLC QoS MAC add 处理函数 `0x43138c`
  - `body.qos_mac_priority` -> `cgi_value` 返回 -> PLC 规则条目第一个 token -> `get_string_segment(..., 0, " ")` 返回值 -> `strcpy(sp+0x30, token)`
  - 被溢出的 `sp+0x30` 邻接 `sp+0x40/sp+0x50/...` 局部变量 -> 后续第二次 `get_string_segment(..., 1, " ")` 返回 `NULL` -> `strcpy(sp+0x70, NULL)` 导致最终 `SIGSEGV`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 收到 `POST /apply.cgi?upgrade_check_free.cgi`，`submit_flag=plc_qos_mac_add` 命中 PLC QoS MAC add 分支。
  2. `0x4313c4` 读取 `qos_mac_priority`，`0x431410` 用 `"%s %s"` 组装条目并交给 `add_items/plc_rules_file_update`。
  3. `plc_rules_file_update@0x430904` 调用 `fcn.00430780@0x430780` 回读和解析该条目。
  4. 第一次 `get_string_segment` 取出 32 字节 `qos_mac_priority`，`0x430860` 执行 `strcpy(sp+0x30, token)` 覆盖相邻栈变量。
  5. 后续第二次 `get_string_segment` 经 `0x4306f8 -> 0x430760` 返回 `NULL`，trace 停在 `0x430894`，随后因 `strcpy(..., NULL)` 触发 `SIGSEGV si_addr=NULL`。

## 原始请求还原

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- handler 来源: `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 关键 body 字段:
  - `submit_flag=plc_qos_mac_add`
  - `qos_mac_priority=<32字节 '2...'>`
  - `plc_qos_mac_addr=22222222`

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main = 0x4047d4`
- 入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键 PC:
  - `pc=0x43138c`
  - `pc=0x431430`
  - `pc=0x430904`
  - `pc=0x43084c`
  - `pc=0x430894`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键数据流与地址

前置 handler `0x43138c` 与其它 `plc_qos_mac_add` 样本相同:

- `0x4313c4`: `cgi_value("qos_mac_priority", ...)`
- `0x4313e8`: `cgi_value("plc_qos_mac_addr", ...)`
- `0x431410`: `sprintf(sp+0x18, "%s %s", qos_mac_priority, plc_qos_mac_addr)`
- `0x431428`: `add_items("plc_qos_mac", entry)`
- `0x431438`: `plc_rules_file_update(...)`

真正的危险写发生在 `fcn.00430780`：

- `s4 = sp+0x30`
- `s3 = sp+0x40`
- `s2 = sp+0x70`
- `0x43084c`: `get_string_segment(s1, 0, " ")`
- `0x430860`: `strcpy(sp+0x30, first_token)`

由于 `sp+0x30` 到下一个局部区 `sp+0x40` 只有 `0x10 = 16` 字节，而本样本 `len(qos_mac_priority) = 32`，第一次 `strcpy` 就会把后续局部变量覆盖掉。trace 之后继续执行：

- `0x430868`: 调用 `fcn.00430368`
- `0x43088c`: 第二次 `get_string_segment(s1, 1, " ")`
- `0x4306f8 -> 0x430760`: 返回 `NULL`
- `0x430894`：回到调用方准备继续复制，随后崩溃

因此这个 case 的真实漏洞链是“长 `qos_mac_priority` 先打坏栈局部变量，再诱导后续 `NULL` 指针崩溃”，不是普通环境噪声。

## 崩溃证据

trace 尾部能直接对齐这个过程:

1. `0x43084c -> 0x430750`：第一次 `get_string_segment` 正常返回
2. `0x430854..0x430860`：第一次 `strcpy` 写入 `sp+0x30`
3. `0x43088c -> 0x4306f8 -> 0x430760`：第二次 `get_string_segment` 走空返回路径
4. `0x430894` 后进程立即 `SIGSEGV si_addr=NULL`

控制台同样显示 `plc_qos_mac1=Unknown` 后崩溃，符合 PLC 规则条目异常导致的解析失败。

## 结论

这是确认漏洞：

- source 明确：`qos_mac_priority` 由 `cgi_value` 读取
- sink 明确：`fcn.00430780` 中的 `strcpy(sp+0x30, first_token)` 无边界复制
- 数据流闭环：`body.qos_mac_priority -> 规则条目 -> get_string_segment -> strcpy`
- trace/console 与后续 `NULL` 崩溃相互印证

因此该 case 应判定为 `确认漏洞`，根因为 PLC QoS MAC 规则解析代码把超长优先级字段复制进过小的栈缓冲。
