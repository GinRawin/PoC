## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / DoS
- Source位置: `0x437d2c` 调用 `cgi_value("tx_power_ctrl_an", $s3, $s4)`；返回值在 `0x437d4c` 被搬到 `$a1`
- Sink位置: `0x437d50` 调用 `nvram_set("wla_txctrl_web", $a1)`；当 `$a1 == NULL` 时在被调函数内触发 `SIGSEGV si_addr=NULL`
- 一句话根因: `submit_flag=wlan_adv` 进入 `config_wladv` 路径后，代码读取不存在的 body 字段 `tx_power_ctrl_an`，`cgi_value` 返回 `NULL`，随后未经判空直接传给 `nvram_set("wla_txctrl_web", NULL)`，导致空指针崩溃。
- 数据包字段 -> 变量赋值:
- `request.method=POST`, `request.handler_name=apply.cgi` -> 原始请求 URL 为 `/apply.cgi`
- `body.submit_flag=wlan_adv` -> 控制流进入 `config_wladv` / `config_wladv_bg` 处理链
- `body.tx_power_ctrl_an` -> 当前请求体中不存在该键；`0x437d2c` 处 `cgi_value("tx_power_ctrl_an", ...)` 因未命中返回 `NULL`
- `0x437d4c move $5, $2` -> 将上一步返回的 `NULL` 赋给 `nvram_set` 的第二个参数
- 执行顺序:
1. `uhttpd` 收到 `POST /apply.cgi`
2. `body.submit_flag=wlan_adv` 使程序进入 `config_wladv` 相关分支
3. 代码依次处理 `wl_enable_router`、`wla_enable_router`、`wds_change_ip`、`tx_power_ctrl` 等字段，并执行 `/etc/rc.d/wps_led.sh WPS_OVER &`
4. `0x437d2c` 读取缺失字段 `tx_power_ctrl_an`，`cgi_value` 返回 `NULL`
5. `0x437d50` 把该 `NULL` 作为值传给 `nvram_set("wla_txctrl_web", ...)`
6. trace 在 `0x437d44` 之后直接落入 `SIGSEGV si_addr=NULL`

## 与代表样本对比

- 当前 case 不需要依赖“同类崩溃族”推断；仅凭本目录内的请求、trace、console 和反汇编就能独立闭环。
- 之前的“证据不足”来自没有把具体字段闭到真实 sink。本次重新核验后，真正触发崩溃的不是那些超长噪声字段，而是缺失的 `tx_power_ctrl_an`。
- 因此本样本应从 `证据不足` 升级为 `确认漏洞`。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi`
- handler: `apply.cgi`
- 关键 body 字段:
- `submit_flag=wlan_adv`
- `tx_power_ctrl=2222...`
- `wl_tx_ctrl=1`
- `wl_txctrl=1`
- `tx_power_ctrl_an` 不存在
- 以上 URL/handler 来自 `VulPacket.json.packet_1.request`
- `show_traffic=debuginfo.htm` 只是 body 参数，不是原始 URL

## Trace映射与关键证据

- `trace_summary.json` 将入口 `main=0x4047d4` 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- `trace/usr_sbin_uhttpd.txt` 第 `746` 行起进入 `0x4375e8` 附近，对应 `config_wladv` 路径
- `container.console.log` 同步打印:
- `=================config_wladv Enter===========`
- `=================STEP 1===========`
- `=================STEP 2===========`
- `=================STEP 3===========`
- `=================config_wladv_bg Enter===========`
- `[qemu] doing qemu_execven on filename /bin/sh`
- `[qemu] doing qemu_execven on filename /etc/rc.d/wps_led.sh`
- trace 关键执行顺序:
- `763: pc=0x437768` -> 读取 `wl_enable_router`
- `764: pc=0x437784` -> 读取 `wla_enable_router`
- `792: pc=0x437aec` -> 调用 `system("/etc/rc.d/wps_led.sh WPS_OVER &")`
- `806: pc=0x437bf4` -> 读取 `wds_change_ip`
- `809: pc=0x437c2c` -> 读取 `tx_power_ctrl`
- `828: pc=0x437ce0` -> 前一条 `cgi_value("wla_enable_router", ...)` 返回
- `831: pc=0x437d2c` -> 调用 `cgi_value("tx_power_ctrl_an", ...)`
- `832: pc=0x40b514` -> 从 `cgi_value` 返回，未命中时返回 `NULL`
- `833: pc=0x437d44` -> 准备调用 `nvram_set("wla_txctrl_web", NULL)`
- `834: --- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## Source -> Variable -> Sink

- Source callsite:
- `0x437d2c: lw $25, -0x7af4($gp)` 解析到动态符号 `cgi_value`
- `0x437d38: addiu $4, $4, -0x1e3c` -> `$a0 = 0x45e1c4 = "tx_power_ctrl_an"`
- `0x437d40: move $5, $19` -> `$a1 = CGI 键值表指针`
- delay slot `move $6, $20` -> `$a2 = 键值表项数`
- `cgi_value` 本体在 `0x40b4a4`; 若遍历结束未命中，则直接在 `0x40b514` 返回当前 `$v0`，即 `NULL`
- 该请求体确实没有 `tx_power_ctrl_an`，因此这里的最合理结果就是 `NULL`

- Variable 传播:
- `0x437d44: lui $4, 0x46`
- `0x437d4c: move $5, $2`
- 其中 `$2` 是 `cgi_value("tx_power_ctrl_an", ...)` 的返回值；此处被原样搬到 `$a1`

- Sink callsite:
- `0x437d50: lw $25, -0x7c10($gp)` 解析到动态符号 `nvram_set`
- `0x437d58: addiu $4, $4, -0x1e28` -> `$a0 = 0x45e1d8 = "wla_txctrl_web"`
- 实际调用语义为 `nvram_set("wla_txctrl_web", NULL)`
- trace 在进入 `0x437d44` 这个 TB 后立即 `SIGSEGV si_addr=NULL`，与 `nvram_set` 对空值做字符串处理时解引用 `NULL` 一致

## 结论与证据闭环

- 可解释的 source: 有。`cgi_value("tx_power_ctrl_an", ...)` 的调用点、实参和返回语义都已核验。
- 可解释的 sink: 有。`nvram_set("wla_txctrl_web", value)` 的调用点和实参都已核验。
- 可解释的数据流: 有。缺失字段 `tx_power_ctrl_an` -> `cgi_value` 返回 `NULL` -> `$v0/$a1` -> `nvram_set("wla_txctrl_web", NULL)` -> `NULL` 解引用崩溃。
- 与 trace / console / 反汇编一致的证据闭环: 有。控制台日志确认 `wlan_adv` 分支，trace 确认执行顺序和崩溃点，动态符号/GOT 解析确认 `cgi_value` 与 `nvram_set` 的真实语义。
- 最合理结论: 这是 `wlan_adv` 处理链中的真实空指针解引用漏洞，触发条件是请求缺失 `tx_power_ctrl_an` 键，而不是任何超长字符串本身。
