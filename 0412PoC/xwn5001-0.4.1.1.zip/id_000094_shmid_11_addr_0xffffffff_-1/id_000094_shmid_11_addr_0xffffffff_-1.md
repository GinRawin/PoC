## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` 函数 `fcn.00430780@0x430780` 内 `strcpy@0x4308a0`
- Source位置: `/usr/sbin/uhttpd` 函数 `0x43138c` 内 `cgi_value("plc_qos_mac_addr")@0x4313e8`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `plc_qos_mac_add` 把用户提供的长 `plc_qos_mac_addr` 写入 PLC 规则条目后，在 `fcn.00430780` 中再次取出第二个 token 并用 `strcpy` 复制到 `sp+0x70`，导致 256 字节字符串覆盖仅 68 字节外的返回地址附近栈区并崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/"` + `request.handler_name="apply.cgi?upgrade_check_free.cgi"` -> 原始请求 URL `/apply.cgi?upgrade_check_free.cgi`
  - `body.submit_flag="plc_qos_mac_add"` -> 进入 PLC QoS MAC add 处理函数 `0x43138c`
  - `body.plc_qos_mac_addr` -> `cgi_value` 返回 `v0` -> `sprintf("%s %s")` 的第二个参数 -> `add_items("plc_qos_mac", entry)` 写入规则条目
  - 规则条目中的第二个 token -> `get_string_segment(..., 1, " ")` 返回值 -> `strcpy(sp+0x70, token)` -> 覆盖 `ra@sp+0xb4`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?upgrade_check_free.cgi`，`submit_flag=plc_qos_mac_add` 命中 `0x43138c`。
  2. `0x4313e8` 读取 `plc_qos_mac_addr`，`0x431410` 用 `"%s %s"` 组装条目并经 `add_items/plc_rules_file_update` 保存。
  3. `plc_rules_file_update@0x430904` 调用 `fcn.00430780@0x430780` 重新解析该条目。
  4. `0x43088c` 取出第二个字段，`0x4308a0` 执行 `strcpy(sp+0x70, token)`。
  5. trace 走到 `0x4308a8` 后立即 `SIGSEGV`，`si_addr=0x3232327a`，与输入中的攻击者字节模式一致。

## 原始请求还原

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- handler 来源: `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 与漏洞直接相关的 body 字段:
  - `submit_flag=plc_qos_mac_add`
  - `qos_mac_priority=0`
  - `plc_qos_mac_addr=<256字节 '2...'>`

`body` 里的 `/tmp/rules.txt` 等键只是参数名，不是原始请求 URL。

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main = 0x4047d4`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键执行链:
  - `pc=0x43138c`
  - `pc=0x431430`
  - `pc=0x430904`
  - `pc=0x43084c`
  - `pc=0x430894`
  - `pc=0x4308a8`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x3232327a} ---`

## 关键数据流与地址

PLC QoS MAC add 处理函数 `0x43138c` 与 `id:000092` 相同，先读取两个 CGI 字段并创建条目:

- `0x4313c4`: `cgi_value("qos_mac_priority", ...)`
- `0x4313e8`: `cgi_value("plc_qos_mac_addr", ...)`
- `0x431410`: `sprintf(sp+0x18, "%s %s", qos_mac_priority, plc_qos_mac_addr)`
- `0x431428`: `add_items("plc_qos_mac", sp+0x18)`
- `0x431438`: `plc_rules_file_update(...)`

本样本里 `qos_mac_priority` 很短，前面的 `sprintf` 总长度只有 `259` 字节，没有越过 `0x43138c` 当前栈帧的 `ra@sp+0x124`。真正触发崩溃的是后续解析链中的第二个无界复制:

- `fcn.00430780@0x430780` 的本地缓冲 `s2 = sp+0x70`
- 保存的 `ra` 在 `sp+0xb4`
- `sp+0x70` 到 `ra` 仅 `0x44 = 68` 字节
- `0x43088c`: `get_string_segment(s1, 1, " ")` 取回第二个 token，即长 `plc_qos_mac_addr`
- `0x4308a0`: `strcpy(sp+0x70, token)`

因为 `len(plc_qos_mac_addr) = 256`，这次 `strcpy` 必然覆盖 `ra` 及其后的保存寄存器。

## 崩溃证据

trace 尾部严格对应 `strcpy` 之后的崩溃:

1. `0x43084c -> 0x430750`：第一次 `get_string_segment`
2. `0x430854..0x430870`：中间处理
3. `0x430894`：准备把第二个 token 复制到 `sp+0x70`
4. `0x4308a8`：`strcpy` 返回后的下一基本块
5. 立即出现 `SIGSEGV si_addr=0x3232327a`

控制台同样显示:

- `plc_qos_mac1=Unknown`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`

`0x3232327a` 对应用户输入中的 `'2'/'z'` 模式，不符合环境随机崩溃。

## 结论

这是确认漏洞，不是误报:

- source 明确: `plc_qos_mac_addr` 由 `cgi_value` 直接读取
- sink 明确: `fcn.00430780` 中的 `strcpy(sp+0x70, token)` 是真实危险写入
- 数据流闭环: `body.plc_qos_mac_addr -> PLC 规则条目 -> get_string_segment -> strcpy`
- trace/console 与崩溃地址都和该链一致

因此该 case 应判定为 `确认漏洞`，根因为 PLC QoS MAC 规则解析代码对用户可控 token 使用了无界 `strcpy`。
