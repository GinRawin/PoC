# 漏洞分析: wndr37avv2-1.0.0.10 / id:000006,sig:11,src:000154,time:309286,execs:2998,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd` `0x0040f178` -> `0x0043afd0 (imp.atoi)`
- Source位置: `/usr/sbin/uhttpd` `0x0040f15c` -> `0x0040f16c (cgi_value("select_editnum_mac"))`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL pointer dereference / DoS`
- 一句话根因: `qos_editmac` 处理路径从 POST 参数中读取 `select_editnum_mac`，`cgi_value` 未命中时返回 `NULL`，随后代码在未判空的情况下直接调用 `atoi(NULL)`，触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag="qos_editmac"` -> `cgi_setobject()` 中 `s1=v0`，作为函数表匹配键，决定进入对应处理函数
  - `body.select_editnum_mac` 缺失 -> `0x40f16c` 调用 `cgi_value("select_editnum_mac")` 返回 `v0=NULL`
  - `v0=NULL` -> `0x40f180` `a0=v0` -> `0x43afd0 imp.atoi(a0)` 崩溃
- 执行顺序:
  1. `handle_request(0x4071b8)` 根据请求命中 `POST /apply.cgi?...`，进入 `post_apply(0x406148)`
  2. `post_apply` 调用 `cgi_setobject(0x4168ec)`；`cgi_setobject` 先读取 `submit_flag`，用其在函数表中匹配到 `qos_editmac` 对应处理函数
  3. 该处理函数在 `0x40f15c-0x40f17c` 读取 `select_editnum_mac` 并直接送入 `atoi`，因字段缺失返回 `NULL` 而在 `0x43afd0` 崩溃

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndr37avv2-1.0.0.10/wndr37avv2_1.0.0.10/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x00404574`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `trace/usr_sbin_uhttpd.txt`
- 关键pc地址:
  - `0x4071b8` -> `handle_request`
  - `0x406148` -> `post_apply`
  - `0x4168ec` -> `cgi_setobject`
  - `0x409060` -> `cgi_value`
  - `0x40f128` -> `qos_editmac` 命中后的未命名处理函数
  - `0x43afd0` -> `imp.atoi`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name="apply.cgi?/USB_browse.htm?openfile=USB_Folder_creat.htm"` 控制请求走入 `apply.cgi` 处理路径，trace 中对应 `handle_request -> post_apply`
  - `body.submit_flag="qos_editmac"` 控制 `cgi_setobject` 选择具体 handler；`0x416944-0x416954` 读取该键，`0x4169d8-0x4169e4` 进行字符串匹配，`0x4169a4` 调用命中的函数指针
  - `body.select_editnum_mac` 本应提供数值参数，但本数据包中缺失；因此 `cgi_value("select_editnum_mac")` 返回 `NULL`
- 哪个函数读取了source字段:
  - `cgi_value(0x409060)` 负责从 POST 参数表中查找键值；在 `0x4090cc` 未命中时显式执行 `move v0, zero` 返回 `NULL`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 本 crash 不涉及复杂拼接；危险值直接来自 `cgi_value("select_editnum_mac")` 的返回值
  - 同一处理函数后续还会用 `sprintf("qos_mac_list%d", atoi_result)` 生成配置键，但程序在更早的 `atoi(NULL)` 处已崩溃
- 最终如何到达sink:
  - `0x40f15c` 装载字符串 `"select_editnum_mac"`
  - `0x40f16c` 调用 `cgi_value`
  - `0x4090cc` 因未找到该 POST 字段返回 `v0=NULL`
  - `0x40f178` 取 `imp.atoi`
  - `0x40f180` 执行 delay slot `move a0, v0`，即 `a0=NULL`
  - `0x43afd0` 执行 `atoi(NULL)`，trace 与容器日志均显示随后收到 `SIGSEGV`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 崩溃点是确定的真实解引用错误，不是模拟器噪声。trace 明确给出 `0x43afd0 -> SIGSEGV si_addr=NULL`，而反汇编证明该地址是 `imp.atoi`，且调用前的 delay slot 明确把 `cgi_value` 的返回值送入 `a0`
  - `cgi_value` 在未命中键时返回 `NULL` 的行为也被反汇编直接验证，因此根因链条完整
- 当前缺失的证据:
  - 未精确恢复 `0x40f128` 所在函数的源码级名称；当前只能确认它是 `submit_flag=qos_editmac` 命中的处理函数
  - 这不影响漏洞判定，因为 source、selector、sink 和崩溃实参都已被真实调用点核验
- 对当前现象的替代解释:
  - 最合理的替代解释是“`submit_flag` 命中了一个要求额外参数的合法流程，但请求缺字段导致空指针崩溃”
  - 这仍然属于真实可触发的拒绝服务漏洞，而不是误报

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `pc=0x416984 -> pc=0x40f570 -> pc=0x40f128 -> pc=0x4090cc -> pc=0x40f174 -> pc=0x43afd0 -> --- SIGSEGV {si_addr=NULL} ---`
  - `trace/usr_sbin_uhttpd.txt` 中完整调用链: `0x4071b8(handle_request) -> 0x406148(post_apply) -> 0x4168ec(cgi_setobject) -> 0x409060(cgi_value submit_flag) -> 0x416984(handler call) -> 0x40f128 -> 0x4090cc(cgi_value miss) -> 0x43afd0`
- 关键容器日志行:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x416948`: `addiu a0, a0, 0x20c`，字符串为 `"submit_flag"`
  - `0x4169d8-0x4169e4`: 用 `strcmp` 比较函数表项与 `submit_flag`，命中后跳到 `0x416984`
  - `0x41698c`: 从表项取函数指针；`0x4169a4`: `jalr t9` 调用命中的 handler
  - `0x40f168`: 字符串为 `"select_editnum_mac"`；`0x40f16c`: `jalr sym.cgi_value`
  - `0x4090cc`: `move v0, zero`，说明 `cgi_value` 未命中时返回 `NULL`
  - `0x40f178-0x40f180`: `jalr imp.atoi`，delay slot 为 `move a0, v0`，把 `NULL` 作为实参传给 `atoi`
