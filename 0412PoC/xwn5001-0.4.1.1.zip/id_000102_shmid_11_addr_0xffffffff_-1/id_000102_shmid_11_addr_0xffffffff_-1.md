## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` 函数 `0x4376dc` 内 `strcmp@0x4377b4`
- Source位置: `/usr/sbin/uhttpd` 函数 `0x4376dc` 内 `cgi_value("wla_enable_router")@0x437798`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `config_wladv` 路径直接把缺失的 `wla_enable_router` CGI 参数送进 `strcmp`，没有做空指针检查，导致 `strcmp(NULL, "0")` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/"` + `request.handler_name="apply.cgi?debuginfo.htm"` -> 原始请求 URL `/apply.cgi?debuginfo.htm`
  - `body.submit_flag="wlan_adv"` -> 命中 `config_wladv` 处理路径
  - `body.wl_enable_router="1"` -> `cgi_value("wl_enable_router")@0x437778` 返回非空
  - `body` 中缺少 `wla_enable_router` -> `cgi_value("wla_enable_router")@0x437798` 返回 `NULL` -> `s1`
  - `s1(NULL)` -> `strcmp(s1, const)@0x4377b4` -> `SIGSEGV si_addr=NULL`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?debuginfo.htm`，`submit_flag=wlan_adv` 进入 `config_wladv`。
  2. 函数先处理 `ap_netbiosname` 等前置逻辑并打印 `config_wladv` 日志。
  3. `0x437778` 读取 `wl_enable_router`，`0x437798` 读取 `wla_enable_router`。
  4. `0x4377b4` 将 `wla_enable_router` 返回值直接传给 `strcmp`。
  5. trace 在 `0x437840` 前后结束并收到 `SIGSEGV si_addr=NULL`。

## 原始请求还原

- 方法: `POST`
- URL: `/apply.cgi?debuginfo.htm`
- handler 来源: `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 关键 body 字段:
  - `submit_flag=wlan_adv`
  - `wl_enable_router=1`
  - 缺失 `wla_enable_router`

这里要区分清楚：`body` 中没有 `wla_enable_router`，这正是崩溃原因；它不是 URL。

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main = 0x4047d4`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键执行片段:
  - `pc=0x4375e8`
  - `pc=0x4376dc`
  - `pc=0x4377a4`
  - `pc=0x4377bc`
  - `pc=0x4377dc`
  - `pc=0x437800`
  - `pc=0x437838`
  - `pc=0x437840`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键反汇编与数据流

`0x4376dc` 起的 `config_wladv` 相关逻辑中，关键指令如下：

- `0x437778`: `cgi_value("wl_enable_router", ...)`
- `0x437798`: `cgi_value("wla_enable_router", ...)`
- `0x4377a0`: `move s1, v0`
- `0x4377ac`: `move a0, s1`
- `0x4377b0`: 准备比较常量
- `0x4377b4`: `strcmp(s1, const)`

字符串表能对齐字段名：

- `0x5e000`: `wl_enable_router`
- `0x5e014`: `wla_enable_router`
- `0x5df78`: `ap_netbiosname`

本样本 body 只提供了 `wl_enable_router`，没有提供 `wla_enable_router`，因此 `cgi_value("wla_enable_router")` 返回 `NULL`。函数没有做任何判空，直接把该指针交给 `strcmp`，于是触发空指针崩溃。

## 崩溃证据

控制台日志：

- `=================config_wladv Enter===========`
- `ap_netbiosname=Unknown`
- `=================STEP 1===========`
- `=================STEP 2===========`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`

trace 没有出现子进程或外部命令，崩溃完全发生在 `uhttpd` 内部。`si_addr=NULL` 与 `strcmp(NULL, ...)` 完全一致，也和缺失字段的反汇编证据一致。

## 结论

这是确认漏洞：

- source 明确：`cgi_value("wla_enable_router")`
- sink 明确：`strcmp@0x4377b4`
- 数据流明确：缺失字段 -> `NULL` 指针 -> `strcmp`
- trace/console/反汇编三者闭环一致

因此该 case 应判定为 `确认漏洞`，根因为 `config_wladv` 对缺失的 `wla_enable_router` 参数没有做空指针校验。
