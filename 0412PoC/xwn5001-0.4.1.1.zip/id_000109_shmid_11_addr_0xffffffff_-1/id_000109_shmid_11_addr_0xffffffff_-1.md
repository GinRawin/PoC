## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` 函数 `0x437cbc` 内 `nvram_set@0x437d54`
- Source位置: `/usr/sbin/uhttpd` 函数 `0x437cbc` 内 `cgi_value("tx_power_ctrl_an")@0x437d3c`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `config_wladv_bg` 路径读取缺失的 `tx_power_ctrl_an` 参数后，直接把返回的 `NULL` 传给 `nvram_set("wla_txctrl_web", NULL)`，导致空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/"` + `request.handler_name="apply.cgi?debuginfo.htm"` -> 原始请求 URL `/apply.cgi?debuginfo.htm`
  - `body.submit_flag="wlan_adv"` -> `config_wladv -> config_wladv_bg` 路径
  - `body.tx_power_ctrl="0"` 存在，但 `body` 中缺少 `tx_power_ctrl_an`
  - 缺失 `tx_power_ctrl_an` -> `cgi_value("tx_power_ctrl_an")` 返回 `NULL` -> `v0`
  - `v0(NULL)` -> `nvram_set("wla_txctrl_web", v0)` -> `SIGSEGV`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 处理 `POST /apply.cgi?debuginfo.htm`，进入 `config_wladv`。
  2. 函数继续进入 `config_wladv_bg`，先异步执行固定命令 `/etc/rc.d/wps_led.sh WPS_OVER &`。
  3. `0x437d3c` 调用 `cgi_value("tx_power_ctrl_an")` 读取 11a/11g 对应的发射功率字段。
  4. 因该字段缺失，`v0=NULL`；`0x437d54` 继续调用 `nvram_set("wla_txctrl_web", NULL)`。
  5. trace 停在 `0x437d44` 前后，并收到 `SIGSEGV si_addr=NULL`。

## 原始请求还原

- 方法: `POST`
- URL: `/apply.cgi?debuginfo.htm`
- handler 来源: `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 关键 body 字段:
  - `submit_flag=wlan_adv`
  - `tx_power_ctrl=0`
  - 缺失 `tx_power_ctrl_an`

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main = 0x4047d4`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键执行片段:
  - `pc=0x437cbc`
  - `pc=0x437d2c`
  - `pc=0x40b514`
  - `pc=0x437d44`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键反汇编与数据流

`config_wladv_bg` 相关逻辑中，`0x437cbc` 之后的关键指令为：

- `0x437d30..0x437d3c`: `cgi_value("tx_power_ctrl_an", ...)`
- `0x437d44`: 把返回值放入 `a1`
- `0x437d50..0x437d54`: `nvram_set("wla_txctrl_web", v0)`

字符串表对齐：

- `0x5e190`: `tx_power_ctrl_an`
- `0x5e1a4`: `wla_txctrl_web`
- `0x5145c`: `/etc/rc.d/wps_led.sh WPS_OVER &`

本样本只提供了 `tx_power_ctrl`，没有对应的 `tx_power_ctrl_an`。因此 `cgi_value("tx_power_ctrl_an")` 返回 `NULL`，而代码没有做判空，直接传给 `nvram_set`。

## 固定命令与崩溃关系

trace 和 console 中出现的：

- `execve("/bin/sh", {"sh","-c","/etc/rc.d/wps_led.sh WPS_OVER &",NULL})`
- `execve("/etc/rc.d/wps_led.sh", {"/etc/rc.d/wps_led.sh","WPS_OVER",NULL})`

都是固定脚本调用，不含用户可控命令片段。它们不是漏洞 sink，只是 `config_wladv_bg` 的前置动作。真正导致崩溃的是脚本之后回到父进程执行的 `nvram_set("wla_txctrl_web", NULL)`。

## 结论

这是确认漏洞：

- source 明确：`cgi_value("tx_power_ctrl_an")`
- sink 明确：`nvram_set("wla_txctrl_web", NULL)`
- 数据流闭环：缺失字段 -> `NULL` -> `nvram_set`
- 固定 shell 命令和后续 `SIGSEGV` 可分离解释，不会混淆成命令注入

因此该 case 应判定为 `确认漏洞`，根因为 `config_wladv_bg` 对缺失的 `tx_power_ctrl_an` 没有做空指针校验。
