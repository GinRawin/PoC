## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` 函数 `0x43138c` 内 `sprintf@0x431410`
- Source位置: `/usr/sbin/uhttpd` 函数 `0x43138c` 内 `cgi_value("qos_mac_priority")@0x4313c4`，`cgi_value("plc_qos_mac_addr")@0x4313e8`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `plc_qos_mac_add` 处理函数把两个用户可控字段用 `sprintf(sp+0x18, "%s %s", ...)` 拼进固定栈缓冲，290 字节输入覆盖了仅 268 字节之外的保存寄存器/返回控制数据，后续在 PLC 规则更新链中触发 `SIGSEGV si_addr=0x32323232`。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/"` + `request.handler_name="apply.cgi?upgrade_check_free.cgi"` -> 原始请求 URL `/apply.cgi?upgrade_check_free.cgi`
  - `body.submit_flag="plc_qos_mac_add"` -> 调度到 PLC QoS MAC add 处理函数 `0x43138c`
  - `body.qos_mac_priority` -> `s1` (`cgi_value` 返回) -> `sprintf` arg#1 -> 栈缓冲 `sp+0x18`
  - `body.plc_qos_mac_addr` -> `v0` (`cgi_value` 返回) -> `sprintf` arg#2 -> 栈缓冲 `sp+0x18`
  - `sprintf` 输出总长 `256 + 1 + 32 + 1 = 290` -> 覆盖 `sp+0x18` 之后的保存寄存器，越过 `ra@sp+0x124`（间距 `0x10c = 268`） -> 污染后续 `plc_rules_file_update/get_string_segment` 使用的控制数据
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?upgrade_check_free.cgi`，`body.submit_flag=plc_qos_mac_add` 进入 `0x43138c`。
  2. `0x4313c4` 读取 `qos_mac_priority`，`0x4313e8` 读取 `plc_qos_mac_addr`。
  3. `0x431410` 执行 `sprintf(sp+0x18, "%s %s", s1, v0)`，超长输入覆盖当前栈帧中的保存数据。
  4. 被污染的栈数据继续流入 `add_items@0x40ccfc -> plc_rules_file_update@0x430904 -> get_string_segment`。
  5. trace 在 `0x430750` 附近结束，进程收到 `SIGSEGV`，`si_addr=0x32323232`，与包中大量 `0x32 ('2')` 字节一致。

## 原始请求还原

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- handler 来源: `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 请求体参数:
  - `submit_flag=plc_qos_mac_add`
  - `qos_mac_priority=<256字节 '2...'>`
  - `plc_qos_mac_addr=<32字节 '2...'>`
- 这里的原始 URL 只来自 `request`；`body` 中字段只是 CGI 参数，不是 URL。

## 入口二进制与 Trace 对应

- `binary_summary/trace_summary` 已将入口二进制匹配为 `/usr/sbin/uhttpd`
- `main = 0x4047d4`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键执行片段:
  - `pc=0x43138c`
  - `pc=0x431430`
  - `pc=0x430904`
  - `pc=0x430750`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`

## 关键反汇编与数据流

`0x43138c` 处的 PLC QoS MAC add 处理函数逻辑可以直接对应请求体字段:

- `0x4313b0..0x4313c8`: 调用 `cgi_value("qos_mac_priority", ...)`
- `0x4313dc..0x4313ec`: 调用 `cgi_value("plc_qos_mac_addr", ...)`
- `0x4313fc..0x431410`: 调用 `sprintf(sp+0x18, "%s %s", s1, v0)`
- `0x431424..0x431428`: `add_items("plc_qos_mac", sp+0x18)`
- `0x431434..0x431438`: `plc_rules_file_update(...)`

字符串表也能对齐:

- `0x5b428`: `qos_mac_priority`
- `0x5b43c`: `plc_qos_mac_addr`
- `0x4bd64`: `"%s %s"`
- `0x5b418`: `"plc_qos_mac%d"`

当前函数栈帧大小为 `0x128`，保存的 `ra` 在 `sp+0x124`。危险缓冲位于 `sp+0x18`，到 `ra` 的距离仅 `0x10c = 268` 字节。样本里:

- `len(qos_mac_priority) = 256`
- `len(plc_qos_mac_addr) = 32`
- `sprintf("%s %s")` 实际写入长度 = `256 + 1 + 32 + 1 = 290`

因此该 `sprintf` 必然向上覆盖至少 22 个字节，足以破坏保存寄存器/返回控制数据。

## 崩溃证据

trace 中未逐条落到 `0x431444` 之后的 epilogue，但已经显示溢出后的更新链继续执行:

1. `0x431430` 调用 `plc_rules_file_update`
2. `0x430904` 进入 PLC 规则文件更新函数
3. `0x430780` / `0x43068c..0x430750` 落入 `get_string_segment` / 相关解析逻辑
4. 最终 `SIGSEGV si_addr=0x32323232`

`0x32323232` 直接对应输入中的 `'2'` 字节模式，不像环境随机值。控制台同样打印:

- `plc_qos_mac1=Unknown`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`

这说明崩溃发生在处理 PLC QoS MAC 条目时，而不是网络失败、缺脚本或普通页面逻辑。

## 结论

这是一个可闭环的栈溢出样本，不是误报:

- source 清晰: 两个 CGI 参数分别由 `cgi_value` 读取
- sink 清晰: `sprintf(sp+0x18, "%s %s", ...)` 是无界写入点
- 数据流清晰: `body` 字段 -> 局部指针变量 -> 栈缓冲 -> PLC 规则更新链
- 崩溃证据闭环: trace/console 都落在 PLC QoS 逻辑，`si_addr=0x32323232` 与输入模式一致

因此该 case 应判定为 `确认漏洞`，根因为 `plc_qos_mac_add` 分支对用户可控字段使用了无界 `sprintf`。
