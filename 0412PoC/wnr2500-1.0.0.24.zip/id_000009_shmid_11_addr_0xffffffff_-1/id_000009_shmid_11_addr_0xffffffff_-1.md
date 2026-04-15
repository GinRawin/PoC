## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd 0x4363e8 0x4364c4`
- Source位置: `/usr/sbin/uhttpd 0x4363e8 0x4364b0`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `参数校验缺失`
- 一句话根因: `submit_flag=pptp` 进入 PPTP 配置处理函数后，程序对 `body.pptp_dnsaddr1` 的 `cgi_value` 返回值缺少 NULL 检查，直接把 `NULL` 传给 `strcpy`，触发空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` + `request.prefix=/` + `request.handler_name=apply.cgi?currentsetting.htm` -> 原始请求 URL 为 `/apply.cgi?currentsetting.htm`
  - `body.submit_flag=pptp` -> `cgi_setobject @ 0x40b4bc` 读取后命中 `pptp` 动作表项，跳转到 `0x4363e8`
  - `body.DNSAssign=1` -> `cgi_value("DNSAssign") @ 0x43647c` 返回值 -> `strcpy` -> 栈缓冲区 `sp+0x30`
  - `body.pptp_dnsaddr1` 缺失 -> `cgi_value("pptp_dnsaddr1") @ 0x4364b0` 返回 `NULL` -> `strcpy @ 0x4364c4` 的 `src`
  - `body.show_traffic=BRS_netgear_success.html` 只是请求体参数，当前没有证据表明它参与了本次崩溃
- 执行顺序:
  1. `uhttpd` 接收 `POST /apply.cgi?currentsetting.htm`
  2. `cgi_setobject` 读取 `submit_flag=pptp`，把请求分派到 PPTP 处理函数 `0x4363e8`
  3. 该函数先读取并复制 `DNSAssign`
  4. 随后读取 `pptp_dnsaddr1`，但该字段在当前数据包中缺失，`cgi_value` 返回 `NULL`
  5. 程序仍在 `0x4364c4` 调用 `strcpy(dst=sp+0x50, src=NULL)`，trace 紧接着出现 `SIGSEGV si_addr=NULL`

## 原始请求还原

- 原始请求方法: `POST`
- 原始 URL: `/apply.cgi?currentsetting.htm`
- handler 来源: `VulPacket.json.packet_1.request.handler_name=apply.cgi?currentsetting.htm`
- `body` 中的 `show_traffic=BRS_netgear_success.html`、`DNSAssign=1`、`wan_pptp_server_ip=7` 等都只是请求体参数，不是 URL

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 给出的 `main` 地址: `0x4040b8`
- `trace_summary.json` 已匹配到 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 序列:
  - `pc=0x40b46c` 进入 `cgi_setobject`
  - `pc=0x4363e8` 进入 PPTP 配置处理函数
  - `pc=0x436468 -> 0x436484` 读取 `DNSAssign`
  - `pc=0x43648c -> 0x43649c` 将 `DNSAssign` 复制到栈缓冲区
  - `pc=0x4364a0 -> 0x4364b8` 读取 `pptp_dnsaddr1`
  - 紧接着 `SIGSEGV si_addr=NULL`

## 关键数据流

- `cgi_setobject @ 0x40b46c` 通过 `cgi_value("submit_flag") @ 0x40b4bc` 取得 `pptp`
- trace 在动作表匹配后落到 `0x4363e8`，说明当前请求确实进入了 PPTP 对应回调
- 在 `0x43646c/0x43647c` 处调用 `cgi_value("DNSAssign")`，返回值随后在 `0x436494` 的 `strcpy` 中被复制到 `sp+0x30`
- 在 `0x4364a0/0x4364b0` 处调用 `cgi_value("pptp_dnsaddr1")`
- 该字段并未出现在 `VulPacket.json.body` 中，因此返回值为 `NULL`
- 程序没有检查 `v0` 是否为空，而是在 `0x4364bc/0x4364c4` 直接准备执行 `strcpy(dst=sp+0x50, src=v0)`，最终崩溃

## 关键证据

- `VulPacket.json` 中存在 `submit_flag=pptp`、`DNSAssign=1`，但缺失 `pptp_dnsaddr1`
- 二进制字符串明确包含 `DNSAssign`、`pptp_dnsaddr1`、`pptp_dnsaddr2`
- `objdump` 反汇编显示:
  - `0x43647c` 调用 `cgi_value("DNSAssign")`
  - `0x4364b0` 调用 `cgi_value("pptp_dnsaddr1")`
  - `0x4364c4` 调用 `strcpy`
- trace 与反汇编严格对齐，崩溃发生在第二个 DNS 字段读取后、第三个字段读取前
- `container.console.log` 只有固定的 `artmtd -r sn` 子进程和最终 `SIGSEGV`，没有更强的环境异常解释

## 结论

- 这是一个可解释的请求体参数校验缺失漏洞
- 闭环已经成立:
  - `body.submit_flag=pptp`
  - `body.pptp_dnsaddr1` 缺失
  - `cgi_value("pptp_dnsaddr1") @ 0x4364b0`
  - `strcpy @ 0x4364c4`
  - `SIGSEGV si_addr=NULL`

## 命中benchmark:否

## 0-day:是
