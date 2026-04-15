## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd unknown 0x435c74`
- Source位置: `/usr/sbin/uhttpd unknown 0x435c60`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `内存破坏`
- 一句话根因: BPA 配置分支把 `body.bpa_dnsaddr2` 通过 `cgi_value` 取出后直接 `strcpy` 到局部缓冲，随后把已破坏的指针继续传给 `update_parental_control_by_dns`，最终在 `0x32323232` 上崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name=apply.cgi?ﾌﾇ` -> 进入 `/apply.cgi` CGI 路径；`?ﾌﾇ` 是 request 里的 query 后缀
  - `body.submit_flag=bpa` -> 选择 BPA 配置分支
  - `body.bpa_dnsaddr2` -> `cgi_value("bpa_dnsaddr2", ...) @ 0x435c60` 返回值 -> `strcpy(s0, v0) @ 0x435c74` -> 覆盖 BPA handler 局部状态
  - `body.DNSAssign` -> 参与 BPA/ParentalControl 条件分支，但本例决定性覆盖来自 `bpa_dnsaddr2`
  - 被破坏的 `s0/s3` 指针 -> `update_parental_control_by_dns(a0=s4,a1=s3,a2=s0) @ 0x435c84` -> `SIGSEGV si_addr=0x32323232`
- 执行顺序:
  1. POST `/apply.cgi?ﾌﾇ` 到达 `uhttpd`
  2. `submit_flag=bpa` 把执行流导向 BPA 配置 handler
  3. handler 在 `0x435c60` 读取 `bpa_dnsaddr2`
  4. `0x435c74` 的 `strcpy` 无界复制超长 `2222...` 字符串
  5. 下一步 `0x435c84` 调用 `update_parental_control_by_dns(0x4355d0)` 时已经带入损坏指针，并在 `0x435c8c` 后触发 `SIGSEGV`

## 原始请求还原

- 原始请求方法: `POST`
- 原始 URL: `/apply.cgi?ﾌﾇ`
- `body.bpa_dnsaddr2`、`body.DNSAssign` 等只属于请求体参数，不是原始 URL

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `0x4040b8`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 关键 pc 地址:
  - `0x435c60`: `cgi_value("bpa_dnsaddr2", ...)`
  - `0x435c74`: `strcpy`
  - `0x435c84`: 调用 `update_parental_control_by_dns`
  - `0x4355d0`: `sym.update_parental_control_by_dns`
  - `0x435c8c`: 崩溃前最后一个 pc

## 关键数据流

- `rabin2 -zz` 把 `0x00060894` 解析为字符串 `bpa_dnsaddr2`
- `0x435c54-0x435c60` 处调用 `cgi_value("bpa_dnsaddr2", request, len)`
- `0x435c6c-0x435c74` 处将返回的长字符串直接 `strcpy` 到局部目的缓冲
- 该覆盖会污染随后作为实参传给 `update_parental_control_by_dns` 的 BPA DNS 指针
- trace 中 `si_addr=0x32323232` 与输入中重复字符 `'2'` 完全一致，说明崩溃地址已被用户数据污染

## 关键证据

- `trace/usr_sbin_uhttpd.txt`:
  - `0x435c7c`
  - `0x4355d0`
  - `0x435614`
  - `0x435628`
  - `0x43576c`
  - `0x435c8c`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`
- `radare2`:
  - `0x435c54` 调用 `cgi_value`
  - `0x435c60` 参数字符串地址对应 `bpa_dnsaddr2`
  - `0x435c74` 调用 `strcpy`
  - `0x435c84` 调用 `sym.update_parental_control_by_dns`
- `strings/rabin2`:
  - `0x00060894 ascii bpa_dnsaddr2`
  - `0x00060884 ascii bpa_dnsaddr1`
  - `0x000608a4 ascii hidden_bpa_idle_time`
## 命中benchmark:否

## 0-day:是
