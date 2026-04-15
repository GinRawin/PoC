## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / DoS
- Source位置:
  - 控制分发: `0x40b9a0` 取 `submit_flag`，`0x471aa0` 表项把 `wlan_adv_plc` 映射到 `0x437e0c`
  - 数据source: `0x437e74` 以键名 `wl_enable_LED` 调用 `0x40b4a4` 查参，`0x437e90` 把返回值写入 `$s1/$17`
- Sink位置: `0x437ebc` / `0x437ec0`，把 `$s1/$17` 作为 `strcmp` 第一个实参传入，第二个实参是 `0x45a57c = "off"`
- 一句话根因: `config_wladv_plc` 路径要求请求参数 `wl_enable_LED`，但代码只查值不判空；当该键缺失时，返回的 `NULL` 被直接传给 `strcmp("off")`，随后崩溃
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=apply.cgi?ﾌﾃ` -> 原始请求 URL 是 `/apply.cgi?ﾌﾃ`
  - `body.submit_flag=wlan_adv_plc` -> `0x40b9a0` 查到该值，分发表 `0x471aa0 = { "wlan_adv_plc", 0, 0x437e0c }` 进入 `config_wladv_plc`
  - `body.wl_enable_LED` -> 当前数据包中缺失，`0x437e74` 查参返回 `NULL`，`0x437e90` 保存到 `$s1/$17`
  - `$s1/$17 = NULL` -> `0x437ebc` `move $4, $17`，`0x437ec0` 调 `strcmp($4, "off")`
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi?ﾌﾃ`
  2. `0x40b9a0` 从参数表中查到 `submit_flag=wlan_adv_plc`
  3. `0x471aa0` 分发表命中 `wlan_adv_plc -> 0x437e0c`
  4. `0x437e74` 继续查找 `wl_enable_LED`，因该键缺失而返回 `NULL`
  5. `0x437ebc` / `0x437ec0` 直接执行 `strcmp(NULL, "off")`
  6. trace 在 `0x437eb4` 后立刻报 `SIGSEGV si_addr=NULL`

## 请求与入口

- 原始请求方法: `POST`
- 原始请求 URL: `/apply.cgi?ﾌﾃ`
- `body.show_traffic=apply.cgi` 只是参数值，不是 URL
- 入口二进制: `/usr/sbin/uhttpd`
- `main` 地址: `0x4047d4`
- 入口 trace: `trace/usr_sbin_uhttpd.txt`
- `trace/8_tb_log.txt` 对应的子进程以 `exit(0)` 结束，没有异常信号；本次崩溃留在 `/usr/sbin/uhttpd` 进程内，没有切换到别的二进制

## 关键证据

- `VulPacket.json` 中明确包含 `body.submit_flag = "wlan_adv_plc"`，且当前 body 中不存在 `wl_enable_LED`
- 调度逻辑核验:
  - `0x40b9a0`: `a0 = "submit_flag"`，调用 `0x40b4a4`
  - `0x40b9b8`: 若返回非空则继续分发
  - `0x471aa0`: 表项是 `{ 0x44e224 "wlan_adv_plc", 0x0, 0x437e0c }`
- `0x40b4a4` 语义核验:
  - 该函数遍历 8-byte 的键值对表
  - 对每项执行 `strcmp(target_key, current->key)`
  - 命中时返回 `current->value`
  - 未命中时返回 `NULL`
  - 该函数本身没有默认值逻辑，也没有写 nvram 的副作用
- handler `0x437e0c` 的 source 核验:
  - `0x437e74`: `a0 = 0x45e248 = "wl_enable_LED"`
  - `0x437e7c`: `jalr 0x40b4a4`
  - `0x437e84`: delay slot 把 `$a2` 置为参数个数/边界
  - `0x437e90`: `move $17, $2`，把查参结果保存到 `$s1/$17`
- sink 核验:
  - `0x437eb8`: `lw $25, -0x7dd4($gp)`，该 GOT 槽位解析为 `0x44b5b0 = strcmp`
  - `0x437ebc`: `move $4, $17`
  - `0x437ec4`: delay slot 把 `$5` 置为 `0x45a57c = "off"`
  - 在此之前没有对 `$17` 做空指针检查
- trace 与调用点闭环:
  - `trace/usr_sbin_uhttpd.txt:711` -> `pc=0x437e0c`
  - `trace/usr_sbin_uhttpd.txt:715` -> `pc=0x40b514`，说明查参 helper 已执行并返回
  - `trace/usr_sbin_uhttpd.txt:716` -> `pc=0x437e88`
  - `trace/usr_sbin_uhttpd.txt:717` -> `pc=0x437ea0`
  - `trace/usr_sbin_uhttpd.txt:718` -> `pc=0x437eb4`
  - `trace/usr_sbin_uhttpd.txt:719` -> `SIGSEGV {si_addr=NULL}`
- `container.console.log` 中的 `config_wladv_plc Enter` 与 handler 入口字符串 `0x45e210` 一致；`LED_ON_OFF=Unknown` 仅作辅助，不参与本次核心判定

## Source -> Variable -> Sink

- 控制流:
  - `body.submit_flag = "wlan_adv_plc"`
  - `0x40b9a0` 调 `0x40b4a4("submit_flag", params, count)` 取值
  - `0x471aa0` 分发表命中 `wlan_adv_plc`
  - 执行流进入 handler `0x437e0c`
- 数据流:
  - source: `body.wl_enable_LED`，当前请求中该键缺失
  - `0x437e74` 调 `0x40b4a4("wl_enable_LED", params, count)` 查值
  - 返回值在 `0x437e90` 保存为 `$s1/$17 = NULL`
  - `0x437ebc` 把 `$17` 装入 `strcmp` 的第一个参数寄存器 `$a0`
  - `0x437ec0` 调用 `strcmp($a0, "off")`
  - `strcmp` 对 `NULL` 解引用，触发 `SIGSEGV`

## 结论

- 这是一个可确认的真实漏洞，不是误报
- 真实触发条件不是 body 中那些超长字段，而是 `submit_flag=wlan_adv_plc` 把请求路由到 `config_wladv_plc` 后，handler 继续读取缺失的 `wl_enable_LED`
- 根因是典型的未判空参数使用: 查参函数可能返回 `NULL`，调用点却直接把返回值作为 `strcmp` 的实参
- 当前目录未提供 `analysis_report_template.md`；本报告已按现有任务要求补齐 `摘要`、请求入口、证据、数据流和结论
