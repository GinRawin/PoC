# 漏洞分析: wndrmacv1-1.0.0.20 / id:000011,sig:11,src:000112,time:939009,execs:4987,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.config_add_qos_mac@0x439638 0x4396a8`
- Source位置: `/usr/sbin/uhttpd sym.config_add_qos_mac@0x439638 0x439690`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL` 指针解引用 / DoS
- 一句话根因: `config_add_qos_mac` 在读取 `attached_mac` 后未做空值检查，直接把 `cgi_value("attached_mac")` 的返回值作为 `strcmp()` 第一个实参，缺失该字段时会触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag = "add_qos_mac"` -> `cgi_setobject()` 中 `s1 = cgi_value("submit_flag")`，匹配动作表项 `0x1000084c -> {0x447cf0("add_qos_mac"), 0x12, 0x439638}`，进入 `config_add_qos_mac`
  - `body.attached_mac` 缺失 -> `config_add_qos_mac` 在 `0x439690` 调用 `cgi_value("attached_mac")`，返回 `v0 = NULL`，随后 `0x43969c` 执行 `a0 = v0`
- 执行顺序:
  1. `POST /apply.cgi?` 请求到达 `uhttpd`，`cgi_setobject()` 在 `0x40e0b8` 读取 `submit_flag`，trace 命中 `0x40e0c0 -> 0x40e11c -> 0x40e130`
  2. `cgi_setobject()` 用 `strcmp()` 遍历动作表，命中 `add_qos_mac` 表项并跳转到 `config_add_qos_mac@0x439638`
  3. `config_add_qos_mac()` 在 `0x439690` 读取缺失的 `attached_mac`，随后在 `0x4396a8` 调用 `strcmp(NULL, "qos_mac")`，trace 末尾报 `SIGSEGV`

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x439638 (sym.config_add_qos_mac)`
- 命中的入口trace: `trace/entry_trace.txt` 第 468-484 行显示 `0x439638 -> 0x43924c -> 0x43932c -> 0x40d058 -> 0x43967c -> 0x439698 -> SIGSEGV`
- 子进程trace链: 未使用；入口 trace 已足够闭合控制流与数据流
- 关键pc地址:
  - `0x40e0b8`: `cgi_value("submit_flag")`
  - `0x40e140`: `strcmp(table_name, submit_flag)`
  - `0x40e0f4`: 从命中的表项取函数指针并调用
  - `0x439690`: `cgi_value("attached_mac")`
  - `0x43969c`: `a0 = v0`
  - `0x4396a8`: `jalr strcmp`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `body.submit_flag` 控制 `cgi_setobject()` 选择哪一个动作表项；它不进入崩溃 sink，但保证控制流到达 `config_add_qos_mac`
  - `body.attached_mac` 是真正进入 sink 的字段；本样本里该字段缺失，导致 `cgi_value("attached_mac")` 返回 `NULL`
  - `body.endis_traffic` 在当前崩溃路径中未见流入 sink 的证据
- 哪个函数读取了source字段:
  - `sym.config_add_qos_mac@0x439638` 在 `0x439690` 调用 `sym.cgi_value@0x40cf10`，其参数装载点是 `0x439694`，键名为 `attached_mac`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `sym.cgi_setobject@0x40e058` 在 `0x40e0b8` 读取 `submit_flag`，并在 `0x40e130-0x40e154` 用动作表匹配字符串后跳到目标处理函数
  - `sym.config_add_qos_mac@0x439638` 在 `0x43969c` 直接把 `cgi_value("attached_mac")` 的返回值搬到 `a0`
- 最终如何到达sink:
  - `body.submit_flag="add_qos_mac"` -> `cgi_setobject()` 命中表项 `0x1000084c -> 0x439638`
  - `body.attached_mac` 缺失 -> `cgi_value("attached_mac")` 返回 `NULL`
  - `0x43969c` 执行 `move a0, v0`
  - `0x4396a8` 调用 `strcmp(a0=NULL, a1="qos_mac")`
  - 结果为 `SIGSEGV`，`si_addr=NULL`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。容器日志明确记录 `SIGSEGV`，入口 trace 明确落到 `sym.config_add_qos_mac`，反汇编又证明 `attached_mac` 的返回值未经检查即进入 `strcmp()`。这不是字符串猜测，而是调用点实参级别的闭合证据。
- 当前缺失的证据:
  - 没有运行时寄存器转储，但对本案不是关键缺口；`move a0, v0` 和 `si_addr=NULL` 已足以确认危险实参是 `NULL`
- 对当前现象的替代解释:
  - 最合理的替代解释是“仿真环境异常导致随机崩溃”，但它无法解释 trace 中稳定出现的 `submit_flag` 分派、`cgi_value("attached_mac")` 返回后立即进入 `strcmp()` 的固定执行序列，因此不成立

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x439638`, `pc=0x43967c`, `pc=0x439698`, `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
  - `trace/entry_trace.txt` 第 457-467 行: `0x40e0c0 -> 0x40e11c -> 0x40dfcc -> 0x40e128 -> 0x40e130 -> 0x40e140 -> 0x40e14c -> 0x40e154 -> 0x40e134 -> 0x40e140 -> 0x40e0f0`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.cgi_setobject@0x40e0b8`: 读取 `submit_flag`
  - `0x1000084c`: 表项为 `0x00447cf0 0x00000012 0x00439638`，其中 `0x447cf0 = "add_qos_mac"`
  - `sym.config_add_qos_mac@0x439690`: `jalr sym.cgi_value`，参数键名 `attached_mac`
  - `sym.config_add_qos_mac@0x43969c`: `move a0, v0`
  - `sym.config_add_qos_mac@0x4396a8`: `jalr strcmp`
  - `sym.check_timestamp@0x40dfcc`: 直接返回 `0`，不会阻止本请求到达漏洞路径
