## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `fcn.00437e0c @ 0x437e0c` `strcmp(s1, const) @ 0x437ec0`
- Source位置: `/usr/sbin/uhttpd` `fcn.00437e0c @ 0x437e0c` `cgi_value("LED_ON_OFF") @ 0x437e80`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `submit_flag=wlan_adv_plc` 进入 PLC 高级配置分支后直接读取 `LED_ON_OFF`，字段缺失时 `cgi_value` 返回 `NULL`，代码随后无判空执行 `strcmp(NULL, ...)` 导致崩溃。
- 数据包字段 -> 变量赋值:
  - `packet_1.request.prefix + packet_1.request.handler_name -> POST /apply.cgi`
  - `packet_1.body.submit_flag=wlan_adv_plc -> cgi_setobject @ 0x40b95c -> fcn.00437e0c`
  - `packet_1.body.LED_ON_OFF` 缺失 -> `cgi_value("LED_ON_OFF") @ 0x437e80` 返回 `NULL` -> `s1`
  - `s1(NULL) -> move a0, s1 @ 0x437ebc -> strcmp(a0, const) @ 0x437ec0`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi`。
  2. `cgi_setobject` 读取 `submit_flag=wlan_adv_plc`，进入 `config_wladv_plc` 对应分支 `0x437e0c`。
  3. 分支打印进入日志，然后调用 `cgi_value("LED_ON_OFF")`。
  4. 由于数据包中没有 `LED_ON_OFF`，返回值为空。
  5. 代码继续在 `0x437ebc-0x437ec0` 调用 `strcmp` 比较该空指针，trace 立即以 `SIGSEGV si_addr=NULL` 结束。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi`
- URL 来源: `VulPacket.json` 的 `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 说明: `wlan_adv_plc` 来自 body 的 `submit_flag`，是 handler 选择条件，不是 URL

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `trace_summary.json` 显示 `main = 0x4047d4`
- 命中 trace: `trace/usr_sbin_uhttpd.txt`
- 关键 trace:
  - `pc=0x40b95c`
  - `pc=0x437e0c`
  - `pc=0x437e54`
  - `pc=0x437e6c`
  - `pc=0x437e88`
  - `pc=0x437ea0`
  - `pc=0x437eb4`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键代码证据

- 字符串表:
  - `wlan_adv_plc`
  - `LED_ON_OFF`

- 反汇编关键点:
  - `0x437e7c`: 组装 `LED_ON_OFF` 参数名
  - `0x437e80`: `jal sym.cgi_value`
  - `0x437e90`: `move s1, v0`
  - `0x437e94`: `nvram_get(...)`
  - `0x437ea4`: 若 `nvram_get` 为 `NULL`，用常量默认值填 `s0`
  - `0x437ebc`: `move a0, s1`
  - `0x437ec0`: `jalr t9 ; strcmp`

## 为什么这是确认漏洞

这里的 source、变量和 sink 已经闭环:

- source: `cgi_value("LED_ON_OFF")`
- variable: `s1`
- sink: `strcmp(s1, const)`
- trace: 命中 `0x437e0c -> 0x437eb4 -> SIGSEGV NULL`
- console: 明确打印 `LED_ON_OFF=Unknown`

因此这不是环境脚本失败，也不是普通噪声，而是 `uhttpd` 内部真实的未判空缺陷。
