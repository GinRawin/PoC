# 漏洞分析: wndrmac-1.0.0.10 / id:000006,sig:11,src:000166,time:912437,execs:5579,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.config_apply_qos 0x43ee50 (jalr strcmp)` 
- Source位置: `/usr/sbin/uhttpd sym.config_apply_qos 0x43ee20 / 0x43ee28 (cgi_value("qos_hidden_check"))`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL` 指针解引用 / 远程拒绝服务
- 一句话根因: `config_apply_qos()` 读取 `qos_hidden_check` 时未检查 `cgi_value()` 的返回值是否为 `NULL`，随后直接把该返回值作为 `strcmp()` 的第一个实参，导致崩溃。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag=qos_uplink_bandwidth` -> 控制流进入 QoS apply 路径，并命中 `sym.config_apply_qos`
  - `body.qos_hidden_check` 缺失 -> `v0` from `cgi_value("qos_hidden_check")` -> `s0=NULL`
  - `request.prefix=/apply.cgi?` + `request.handler_name=ap_mode_netmask` -> 保证请求进入对应 CGI 处理路径
- 执行顺序:
  1. 请求以 `POST /apply.cgi?` 进入 `uhttpd`，`submit_flag=qos_uplink_bandwidth` 使控制流进入 QoS 配置处理逻辑。
  2. `sym.config_apply_qos` 在 `0x43ee20/0x43ee28` 调用 `cgi_value("qos_hidden_check")`；该字段在数据包中不存在，`sym.cgi_value` 于 `0x40e3cc` 返回 `NULL`，并在 `0x43ee30` 保存到 `s0`。
  3. 函数在 `0x43ee50` 调用 `strcmp(s0, const)`，由于 `s0=NULL`，在 `0x44b380 -> 0x43ee48` 之后触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x408120`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`；未见额外子进程参与崩溃路径
- 关键pc地址:
  - `0x43ee10`: 为 `cgi_value("qos_hidden_check")` 装载参数
  - `0x43ee2c`: `move s0, v0`
  - `0x44b380`: `unlink` 导入桩
  - `0x43ee50`: `strcmp` 导入调用点
  - `0x40e3cc`: `sym.cgi_value` 未命中时返回 `NULL`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `submit_flag=qos_uplink_bandwidth` 控制 QoS apply 分支。
  - 缺失的 `qos_hidden_check` 决定 `cgi_value("qos_hidden_check")` 返回 `NULL`。
  - `ap_dhcp_ipaddr`、`upgrade_yes_no` 这两个超长字段在当前崩溃链中没有进入 fault site。
- 哪个函数读取了source字段:
  - `sym.config_apply_qos` 在 `0x43ee20/0x43ee28` 调用 `sym.cgi_value("qos_hidden_check", ...)`。
  - `sym.cgi_value` 在 `0x40e390-0x40e3cc` 遍历 CGI 键值表，未命中时在 `0x40e3cc` 令 `v0=0` 返回。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 本案不是字符串内容溢出；攻击者通过“缺失字段”控制 `cgi_value` 的返回值为 `NULL`，随后 `sym.config_apply_qos` 在 `0x43ee30` 将 `v0` 保存到 `s0`。
- 最终如何到达sink:
  - `body.qos_hidden_check` 缺失
  - `sym.config_apply_qos@0x43ee20/0x43ee28` 调用 `sym.cgi_value("qos_hidden_check")`
  - `sym.cgi_value@0x40e3cc` 返回 `NULL`
  - `sym.config_apply_qos@0x43ee30` 执行 `move s0, v0`
  - `sym.config_apply_qos@0x43ee50` 调用 `strcmp(s0, const)`
  - `s0==NULL` 导致 `SIGSEGV`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃由可解释的数据流直接触发，不是仿真噪声。`container.console.log` 和 `entry_trace` 都记录了同一次 `SIGSEGV`；反汇编明确显示 `cgi_value` 可能返回 `NULL`，而 `config_apply_qos` 对该返回值没有判空便传给 `strcmp`。
- 当前缺失的证据:
  - 没有更高层源码级符号去精确展示 `submit_flag=qos_uplink_bandwidth` 与 `sym.config_apply_qos` 的完整分发表遍历代码，但已有 `submit_flag=` 解析逻辑、QoS 相关字符串及 `0x402f60 -> sym.config_apply_qos` 的表项共同支持该控制流。
- 对当前现象的替代解释:
  - 最合理的替代解释是环境异常导致 libc `strcmp` 崩溃，但这与 `sym.cgi_value` 的 `NULL` 返回路径、`move s0, v0`、以及 `strcmp` 的实参装载顺序不符，因此不成立。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x43ee10 -> 0x43ee2c -> 0x44b380 -> 0x43ee48`，随后 `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
  - `trace/usr_sbin_uhttpd.txt` 末尾与入口 trace 一致，说明崩溃发生在 `uhttpd` 本体
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.cgi_value 0x40e390-0x40e3cc`: 遍历键值表；未命中时走到 `0x40e3cc: move v0, zero`
  - `sym.config_apply_qos 0x43ee20-0x43ee30`: 调用 `cgi_value("qos_hidden_check")`，随后 `move s0, v0`
  - `sym.config_apply_qos 0x43ee50-0x43ee58`: `move a0, s0` 后调用 `strcmp`
  - `0x402f60`: 数据表项直接指向 `0x43ed0c sym.config_apply_qos`
  - 字符串证据: 二进制内同时存在 `qos_uplink_bandwidth`、`apply_qos`、`submit_flag=`、`ap_mode_netmask`、`qos_hidden_check`
