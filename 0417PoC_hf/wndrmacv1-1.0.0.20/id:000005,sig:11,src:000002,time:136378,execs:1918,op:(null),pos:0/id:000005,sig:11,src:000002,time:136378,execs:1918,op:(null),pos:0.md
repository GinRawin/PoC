# 漏洞分析: wndrmacv1-1.0.0.20 / id:000005,sig:11,src:000002,time:136378,execs:1918,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd` `fcn.00438fa4` `0x438ff8` (`jalr` 调用 `sym.imp.atoi@0x445880`, delay slot `0x438ffc` 将 `v0` 写入 `a0`)
- Source位置: `/usr/sbin/uhttpd` `fcn.00438fa4` `0x438fe8` (`cgi_value("select_editnum_mac")`)
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / 拒绝服务
- 一句话根因: `edit_qos_mac` 路径在读取 `select_editnum_mac` 后未检查 `cgi_value` 返回值是否为空，直接执行 `atoi(NULL)` 导致 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `request.handler_name=apply.cgi?/pls_wait_reboot.html` -> 命中 `apply.cgi` CGI 处理路径
  - `body.submit_flag=edit_qos_mac` -> `sym.cgi_setobject@0x40e058` 中的 `s1`，用于分发表匹配并进入 `sym.config_edit_qos_mac@0x4396fc`
  - `body.select_editnum_mac` -> `fcn.00438fa4` 中 `cgi_value` 返回值 `v0`
  - 本次样本未提供 `body.select_editnum_mac` -> `v0=NULL` -> delay slot 后 `a0=NULL` -> `atoi`
- 执行顺序:
  1. 请求进入 `apply.cgi` 路径后，`sym.cgi_setobject@0x40e058` 在 `0x40e0b4` 读取 `submit_flag`，并在 `0x40e134-0x40e154` 用 `strcmp` 遍历 `obj.funcs`。
  2. `submit_flag=edit_qos_mac` 使执行流进入 `sym.config_edit_qos_mac@0x4396fc`；该函数先在 `0x439734` 调用 `fcn.004390e4@0x4390e4`，返回后继续在 `0x439764` 跳转到 `fcn.00438fa4@0x438fa4`。
  3. `fcn.00438fa4` 在 `0x438fe4-0x438fe8` 调用 `cgi_value("select_editnum_mac")`，返回 `NULL` 后于 `0x438ff8` 调用 `atoi`，最终触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndrmacv1-1.0.0.20/wndrmacv1_1.0.0.20/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x407940`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt` 与入口 trace 尾部一致，均显示 `0x40cf10 -> 0x4396fc -> 0x4390e4 -> 0x439740 -> 0x438fa4 -> SIGSEGV`
- 关键pc地址:
  - `0x40e0b8`: `cgi_value("submit_flag")`
  - `0x40e134-0x40e154`: 用 `strcmp` 在 `obj.funcs` 中匹配 `submit_flag`
  - `0x4396fc`: `sym.config_edit_qos_mac`
  - `0x4390e4`: 前置处理函数 `fcn.004390e4`
  - `0x438fe4-0x438fe8`: `cgi_value("select_editnum_mac")`
  - `0x438ff4-0x438ff8`: `atoi` 调用点
  - `0x445880`: `sym.imp.atoi`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name=apply.cgi?/pls_wait_reboot.html` 让请求进入 `apply.cgi` CGI 逻辑。
  - `body.submit_flag=edit_qos_mac` 控制 `sym.cgi_setobject` 的分发表匹配结果，决定调用 `sym.config_edit_qos_mac`。
  - `body.select_editnum_mac` 是 `fcn.00438fa4` 期望读取并传给 `atoi` 的字段；本次包中该字段缺失，因此形成 `NULL` 实参。
  - `body.wlg1_endis_guestNet` 与 `body.WzQ` 在已命中的崩溃路径中没有流入 sink。
- 哪个函数读取了source字段:
  - `sym.cgi_setobject@0x40e058` 在 `0x40e0b8` 读取 `submit_flag`。
  - `fcn.00438fa4@0x438fa4` 在 `0x438fe8` 读取 `select_editnum_mac`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 这里没有复杂拼接；危险值直接来自 `cgi_value` 返回值。
  - 对 `submit_flag`，`sym.cgi_setobject` 将返回值保存到 `s1`，随后与分发表项逐个 `strcmp`。
  - 对 `select_editnum_mac`，`fcn.00438fa4` 直接把 `cgi_value` 返回值保存在 `v0`，并在 `0x438ffc` 的 delay slot 中放入 `a0`。
- 最终如何到达sink:
  - `VulPacket.request.handler_name` -> `apply.cgi`
  - `VulPacket.body.submit_flag` -> `sym.cgi_setobject` 中 `s1` -> 命中 `edit_qos_mac` 对应函数指针 -> `sym.config_edit_qos_mac@0x4396fc`
  - `sym.config_edit_qos_mac` -> `fcn.004390e4@0x4390e4` -> 返回 -> `fcn.00438fa4@0x438fa4`
  - 缺失的 `VulPacket.body.select_editnum_mac` -> `cgi_value("select_editnum_mac")==NULL`
  - `NULL` -> `v0` -> `a0` -> `sym.imp.atoi@0x445880`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - `container.console.log` 明确记录 `[GreenHouseQEMU] SIGSEGV CAUGHT!` 和 `SIG 11`。
  - `trace/entry_trace.txt` 与 `trace/usr_sbin_uhttpd.txt` 的尾部都显示执行顺序 `0x4396fc -> 0x4390e4 -> 0x439740 -> 0x438fa4 -> 0x438ff0 -> SIGSEGV`。
  - 反汇编确认 `0x438fe4` 装载字符串 `select_editnum_mac`，`0x438fe8` 调用 `cgi_value`，`0x438ff8` 紧接着调用 `atoi`，中间没有任何空值检查。
  - 崩溃地址 `si_addr=NULL` 与 `atoi(NULL)` 完全一致，因此这不是单纯仿真噪声。
- 当前缺失的证据:
  - 没有寄存器快照直接打印 `a0=NULL`，但 trace、`si_addr=NULL` 与调用点反汇编组合后已经足够闭合证据链。
- 对当前现象的替代解释:
  - 另一种解释只能是 `cgi_value` 内部返回了异常指针；但当前崩溃地址为 `NULL`，且参数字段在样本中确实缺失，更合理解释就是缺失字段导致的空指针解引用。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x4396fc`, `pc=0x4390e4`, `pc=0x439130`, `pc=0x445880`, `pc=0x439140`, `pc=0x439228`, `pc=0x439740`, `pc=0x438fa4`, `pc=0x40cf7c`, `pc=0x438ff0`, `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
  - `trace/usr_sbin_uhttpd.txt` 末尾: `pc=0x40cf10`, `pc=0x40cf7c`, `pc=0x4396fc`, `pc=0x4390e4`, `pc=0x445880`, `pc=0x439140`, `pc=0x439228`, `pc=0x439740`, `pc=0x438fa4`, `pc=0x438ff0`, `--- SIGSEGV ... si_addr=NULL ---`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `sym.cgi_setobject@0x40e058`: `0x40e0b4 addiu a0, a0, ... ; "submit_flag"`，随后 `0x40e134-0x40e154` 使用 `strcmp` 遍历 `obj.funcs`
  - `sym.config_edit_qos_mac@0x4396fc`: `0x439734 addiu t9, t9, -0x6f1c ; 0x4390e4`，返回后 `0x439764 addiu t9, t9, -0x705c ; 0x438fa4`，说明该路径会继续进入第二个处理函数
  - `fcn.004390e4@0x439124`: `addiu a0, a0, 0x5d1c ; "qoslist_editnum"`，随后调用 `config_get` 和 `atoi`，这是前置正常步骤
  - `fcn.00438fa4@0x438fe4`: `addiu a0, a0, 0x5d2c ; "select_editnum_mac"`，随后在 `0x438fe8` 调用 `cgi_value`
  - `fcn.00438fa4@0x438ff4-0x438ff8`: 加载 `sym.imp.atoi` 并调用，delay slot `0x438ffc` 将 `v0` 移入 `a0`
  - 字符串恢复结果: `0x45xxxx+0x5d2c = "select_editnum_mac"`，`0x45xxxx+0x5d40 = "qos_mac_list%d"`，`0x45xxxx+0x5d1c = "qoslist_editnum"`
