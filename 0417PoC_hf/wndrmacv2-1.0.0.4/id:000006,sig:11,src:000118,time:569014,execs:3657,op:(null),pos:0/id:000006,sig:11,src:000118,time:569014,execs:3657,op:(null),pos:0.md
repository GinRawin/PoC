# 漏洞分析: wndrmacv2-1.0.0.4 / id:000006,sig:11,src:000118,time:569014,execs:3657,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd` `config_plc_dev_config@0x42f0e0` `0x42f13c (jalr atoi)`，实际崩溃落在 `sym.imp.atoi@0x4458a0`
- Source位置: `/usr/sbin/uhttpd` `config_plc_dev_config@0x42f0e0` `0x42f128 (jalr cgi_value, key="plc_dev_select_num")`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL pointer dereference`
- 一句话根因: `config_plc_dev_config` 在读取 POST 参数 `plc_dev_select_num` 后没有检查 `cgi_value()` 的返回值是否为 `NULL`，直接把结果传给 `atoi()`，导致空指针解引用崩溃。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag = "plc_dev_config"` -> `cgi_setobject` 中 `s1`，用于在 `obj.funcs` 表中匹配 handler
  - `body.plc_dev_select_num` 缺失 -> `config_plc_dev_config` 中 `v0 = NULL` -> `a0 = NULL` -> `atoi(a0)`
  - `body.filename` / `body.wan_proto` / `body.%20timestamp` -> 本次崩溃路径未见流入 sink，仅为无关噪声
- 执行顺序:
  1. 请求进入 `apply.cgi` 路径后，`cgi_setobject@0x40e058` 通过 `cgi_value("submit_flag")` 取到 `plc_dev_config`
  2. `cgi_setobject` 遍历 `obj.funcs@0x100003f0`，匹配到表项 `"plc_dev_config" -> handler 0x42f0e0`
  3. `config_plc_dev_config@0x42f0e0` 调用 `cgi_value("plc_dev_select_num")` 返回 `NULL`，随后在 `0x42f13c` 调用 `atoi(NULL)` 并在 `0x4458a0` 崩溃

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndrmacv2-1.0.0.4/wndrmacv2_1.0.0.4/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x407940`
- 命中的入口trace: `trace/entry_trace.txt` 末尾显示 `pc=0x4458a0` 后出现 `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- 子进程trace链: `entry_trace` 显示 `24 fork() = 26`, `26 fork() = 29`；`trace/usr_sbin_uhttpd.txt` 在分叉后继续执行并记录到崩溃
- 关键pc地址:
  - `0x40e0a8`: `cgi_setobject` 调用 `cgi_value("submit_flag")`
  - `0x40e130 -> 0x40e154`: 遍历 `obj.funcs` 并匹配 `"plc_dev_config"`
  - `0x42f0e0`: 进入 `config_plc_dev_config`
  - `0x40cf7c`: `cgi_value("plc_dev_select_num")` 未命中时返回 `0`
  - `0x42f13c`: 调用 `atoi`
  - `0x4458a0`: `sym.imp.atoi`，随后 `SIGSEGV`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name = "apply.cgi?/USB_browse.htm?openfile=USB_Folder_creat.htm"` 让请求进入 `apply.cgi` 处理路径
  - `body.submit_flag = "plc_dev_config"` 被 `cgi_setobject` 读取后存入 `s1`，再与 `obj.funcs` 表中的名字逐项比较，选中 `config_plc_dev_config`
  - `body.plc_dev_select_num` 在 `VulPacket.json` 中不存在；因此 `config_plc_dev_config` 对该 key 的查询结果为 `NULL`
- 哪个函数读取了source字段:
  - `config_plc_dev_config@0x42f0e0` 在 `0x42f118/0x42f128` 调用 `cgi_value("plc_dev_select_num", req, ctx)` 读取 source
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 对本次 sink 路径没有额外拼接；危险值由 `cgi_value()` 直接返回给 `v0`
  - `cgi_setobject@0x40e0a8` 读取 `submit_flag`，只负责控制流，不是最终 sink 参数
- 最终如何到达sink:
  - `cgi_value("plc_dev_select_num")` 在 `cgi_value@0x40cf10` 中遍历参数表；未命中时走到 `0x40cf7c` 返回 `0`
  - 返回值 `v0` 在 `config_plc_dev_config` 中经 `move a0, v0` 作为 `atoi` 的实参
  - `atoi` 没有空指针保护，导致 `si_addr=NULL` 的崩溃

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃信号、崩溃地址、控制流和数据流可以闭环解释
  - `submit_flag` 到 handler 的映射由 `obj.funcs` 静态表精确验证，`"plc_dev_config"` 对应的函数指针就是 `0x42f0e0`
  - `cgi_value` 在未找到 key 时明确返回 `0`，trace 中也确实出现了 `0x40cf7c`
  - handler 紧接着在 `0x42f13c` 调用 `atoi`，trace 中的下一站就是 `0x4458a0`，随后 `SIGSEGV`
- 当前缺失的证据:
  - 无影响结论的关键缺失证据；当前证据已足以确认漏洞
- 对当前现象的替代解释:
  - 最合理替代解释是仿真环境或请求解析器先前损坏了参数表，但这与 `submit_flag` 仍能被正常解析且 `cgi_value` 对缺失 key 精确返回 `0` 的证据不符，因此不成立

## 证据

- 关键trace行:
  - `trace/usr_sbin_uhttpd.txt` 尾部: `... 0x40e130 0x40e140 0x40e14c 0x40e154 0x40e134 0x40e140 0x40e0f0 0x42f0e0 0x40cf7c 0x42f130 0x4458a0 --- SIGSEGV ... si_addr=NULL`
  - `trace/entry_trace.txt` 末尾: `pc=0x42f130`, `pc=0x4458a0`, `--- SIGSEGV {si_addr=NULL} ---`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `cgi_setobject@0x40e0a8` 调用 `cgi_value("submit_flag")`，`0x40e130-0x40e154` 遍历 `obj.funcs`
  - `obj.funcs@0x100008c0` 表项为 `0x00447dc4("plc_dev_config"), 0x26, 0x0042f0e0`
  - `config_plc_dev_config@0x42f118-0x42f128`: 加载字符串 `"plc_dev_select_num"` 并调用 `cgi_value`
  - `cgi_value@0x40cf7c`: 未命中参数时返回 `0`
  - `config_plc_dev_config@0x42f13c`: `jalr atoi`，delay slot 为 `move a0, v0`，把 `NULL` 直接传入 `atoi`
