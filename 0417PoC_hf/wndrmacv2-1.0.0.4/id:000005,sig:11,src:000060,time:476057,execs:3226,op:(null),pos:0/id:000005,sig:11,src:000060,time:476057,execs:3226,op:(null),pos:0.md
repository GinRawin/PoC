# 漏洞分析: wndrmacv2-1.0.0.4 / id:000005,sig:11,src:000060,time:476057,execs:3226,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd sym.config_qosmac_del 0x439acc`
- Source位置: `/usr/sbin/uhttpd sym.config_qosmac_del 0x439aa8`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL` 指针解引用 / DoS
- 一句话根因: `submit_flag=qos_delmac` 命中 `config_qosmac_del()` 后，代码对缺失的表单项 `select_editnum_mac` 未做空值校验，`del_items("qos_mac_list", NULL)` 返回 `NULL` 后又立刻执行 `lb 0(s2)`，最终触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag=qos_delmac` -> `cgi_setobject()` 中 `s1`，用于在 `obj.funcs` 表里选中 `sym.config_qosmac_del`
  - `body.select_editnum_mac` 缺失 -> `sym.config_qosmac_del` 中第二次 `cgi_value()` 返回 `v0=NULL`，随后以 `a1=NULL` 传入 `sym.del_items`
  - `body.select_qoslist_num` 缺失 -> `sym.config_qosmac_del` 中第一次 `cgi_value()` 返回值未被校验，但本次崩溃直接由第二个缺失字段链条触发
- 执行顺序:
  1. 请求体中的 `submit_flag=qos_delmac` 被 `cgi_setobject()` 读取，并在函数表中匹配到 `sym.config_qosmac_del`
  2. `sym.config_qosmac_del` 先后调用 `cgi_value("select_qoslist_num")`、`cgi_value("select_editnum_mac")`，第二次返回 `NULL`
  3. `sym.del_items("qos_mac_list", NULL)` 返回 `NULL`，`sym.config_qosmac_del` 随即在 `0x439acc` 对返回指针执行 `lb 0(s2)` 并崩溃

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x407940`
- 命中的入口trace: `trace/entry_trace.txt` 与 `trace/usr_sbin_uhttpd.txt` 一致，尾部为 `0x40e0f0 -> 0x439a4c -> 0x40cf7c -> 0x439a90 -> 0x439ab0 -> 0x40d188 -> 0x40d1d4 -> 0x40d284 -> 0x439ac8 -> SIGSEGV`
- 子进程trace链: `entry_trace.txt` 显示 `uhttpd` 经两次 `fork()` 后继续在 `trace/usr_sbin_uhttpd.txt` 中执行并崩溃，没有发现其他二进制介入该 fault path
- 关键pc地址:
  - `0x40e0b8`: `cgi_setobject()` 调用 `cgi_value("submit_flag")`
  - `0x40e140/0x40e14c/0x40e0f0`: 函数表匹配后跳入 handler
  - `0x439a88`: `config_qosmac_del()` 调用 `cgi_value("select_qoslist_num")`
  - `0x439aa8`: `config_qosmac_del()` 调用 `cgi_value("select_editnum_mac")`
  - `0x439ac0`: 调用 `del_items("qos_mac_list", v0)`
  - `0x439acc`: `lb v1, (s2)`，对 `NULL` 返回值解引用

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `body.submit_flag` 控制 `cgi_setobject()` 的 handler 选择，只负责把执行流带到 `sym.config_qosmac_del`
  - `body.select_editnum_mac` 是 `sym.config_qosmac_del` 期望读取的真实 source 字段；本次请求中该字段缺失，因此 `cgi_value()` 返回 `NULL`
  - `body.New_Language`、`body.GUI_Region`、`body.lang_in_flash`、`body.%20timestamp`、`body.upgrade_yes_no` 没有出现在崩溃路径的寄存器装载和调用参数中
- 哪个函数读取了source字段:
  - `sym.config_qosmac_del` 在 `0x439aa8` 调用 `sym.cgi_value("select_editnum_mac", req, ctx)`，返回值进入 `v0/s2`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 本次不是字符串覆盖型漏洞；危险值没有经过拷贝放大，而是 `cgi_value()` 将缺失字段直接表示为 `NULL`，随后 `sym.del_items` 原样接收该指针作为第二参数
- 最终如何到达sink:
  - `submit_flag=qos_delmac` -> `cgi_setobject()` 选中 `sym.config_qosmac_del` -> `cgi_value("select_editnum_mac")` 返回 `NULL` -> `del_items("qos_mac_list", NULL)` -> 返回 `NULL` 到 `s2` -> `0x439acc` 对 `s2` 解引用崩溃

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。崩溃由请求可控的 handler 选择触发，fault site 为代码中的确定性 `NULL` 解引用，而不是仿真噪声、非法指令或地址随机化造成的偶发停机。
  - `container.console.log` 和 trace 同时给出 `SIGSEGV`，并且 `si_addr=NULL` 与 `0x439acc: lb v1, (s2)` 完全吻合。
  - 崩溃不依赖超长字段覆盖；即使没有 `New_Language` 里的长字符串，只要请求命中 `qos_delmac` 且缺少 `select_editnum_mac`，这条路径仍会走到相同的空指针解引用。
- 当前缺失的证据:
  - 没有运行时寄存器转储直接打印 `s2==NULL`，但 trace、`si_addr=NULL`、以及 `del_items` 在 `a1==NULL` 时直接返回的反汇编已经足够闭合该结论。
- 对当前现象的替代解释:
  - 最合理的替代解释是 `del_items()` 因其他内部条件返回 `NULL`；但无论哪种情况，`config_qosmac_del()` 对返回值缺乏空值检查并立即解引用，仍然构成真实 DoS 漏洞。结合本次请求缺失 `select_editnum_mac`，最直接原因仍是缺失字段导致的空返回值传播。

## 证据

- 关键trace行:
  - `trace/usr_sbin_uhttpd.txt`: `0x40e0f0 -> 0x439a4c -> 0x40cf7c -> 0x439a90 -> 0x439ab0 -> 0x40d188 -> 0x40d1d4 -> 0x40d284 -> 0x439ac8 -> --- SIGSEGV {si_addr=NULL} ---`
  - `trace/entry_trace.txt` 末尾同样记录 `pc=0x439ac8` 后 `SIGSEGV`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.cgi_setobject`:
    - `0x40e0b4/0x40e0b8`: 读取 `submit_flag`
    - `0x40e140/0x40e144`: 将表项字符串与 `submit_flag` 比较
    - `0x40e0f0/0x40e10c`: 命中后取表项函数指针并调用
  - `sym.config_qosmac_del`:
    - `0x439a80/0x439a88`: `cgi_value("select_qoslist_num", ...)`
    - `0x439aac/0x439aa8`: `cgi_value("select_editnum_mac", ...)`
    - `0x439ab4/0x439ac0`: `del_items("qos_mac_list", v0)`
    - `0x439acc`: `lb v1, (s2)`，对返回值直接解引用
  - `sym.del_items`:
    - `0x40d1b4`: `beqz a1, 0x40d1d4`
    - `0x40d1d4/0x40d1d8`: 参数为 `NULL` 时直接返回 `-1`
    - 该函数整体存在多条早退路径，说明 caller 必须检查返回值；但 `sym.config_qosmac_del` 未检查即继续解引用
