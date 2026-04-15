## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `0x406b60` `unknown`
- Source位置: `/usr/sbin/uhttpd` `0x40896c` `0x409c58`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `POST /apply.cgi` 被 `handle_request()` 直接分发到 `0x406b60` 的 `apply.cgi` handler；该 handler 在没有完成后续 CGI action 初始化的情况下立即进入 refresh/redirect 路径，最终在同一条早期执行链上触发 `SIGSEGV`。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name` (`/` + `apply.cgi`) -> 解析后的请求路径 `s1` -> `handle_request` 中与 `"apply.cgi"` 比较 -> 分发表项 `0x471770` -> handler 指针 `0x406b60`
  - `body.show_traffic` / `body.submit_flag` / `body.qos_port_priority` / `body.plc_qos_port` -> 本次 trace 中未见进入 `cgi_setobject(0x40b95c)` 或 `cgi_func(0x40bbc4)`，没有证据证明这些 body 字段在崩溃前到达危险操作
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi`
  2. `handle_request(0x40896c)` 用请求路径匹配 `"apply.cgi"`，装载该 handler 的分发表项
  3. `handle_request` 调用 `0x406b60`
  4. `0x406b60` 在进入真正的 `cgi_func`/`cgi_setobject` 之前就执行 refresh/redirect 相关逻辑
  5. 进程在这条早期路径上直接 `SIGSEGV`，控制台记录 `SIG 11`

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi`
- handler: `apply.cgi`
- 上述 URL/handler 来自 `VulPacket.json` 的 `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- `body.show_traffic=upgrade_check_free.cgi`、`body.submit_flag=upgrade_check_free.cgi` 只是请求体参数值，不是原始请求 URL

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 给出的 `main` 地址为 `0x4047d4`
- `trace_summary.json` 已将入口 trace 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- `trace/usr_sbin_uhttpd.txt` 开头命中 `pc=0x4047d4`，证明该 trace 对应入口 `uhttpd`
- 关键末尾执行链为:
  - `pc=0x405470`
  - `pc=0x4081c8`
  - `pc=0x409c74`
  - `pc=0x409c80`
  - `pc=0x406b60`
  - `--- SIGSEGV ... si_addr=NULL ---`
- `trace/9_tb_log.txt` 只到 `exit(0)`，没有异常，不是漏洞进程

## 关键地址与二进制证据

- `handle_request` 位于 `0x40896c`
- 在 `0x409c58` 到 `0x409c84`，`handle_request` 从分发表读取当前 URL 对应项，并在 `0x409c84` 通过 `jalr t9` 调用 handler
- 分发表中 `0x471770` 处可见 `"apply.cgi"` 字符串指针，且该项的 handler 指针位于 `0x471780 = 0x406b60`
- `0x406b60` 是 `apply.cgi` 的实际处理函数；它开头立即进入 refresh helper 路径，并在真正执行 `cgi_commit` 之前就可能崩溃
- `cgi_setobject(0x40b95c)` 会读取 `submit_flag`
- `cgi_func(0x40bbc4)` 会读取 `submit_flag=...`
- 但本次崩溃 trace 中没有出现 `0x40b95c`、`0x40bbc4` 或其附近 PC，因此现有证据不支持“body 参数先进入 action 逻辑后才崩溃”的解释

## 从输入到崩溃点的数据流

本 case 能闭环的输入链条是“请求路径 -> handler 分发 -> 提前崩溃”：

1. 请求行中的 `/apply.cgi` 被解析为当前请求路径
2. `handle_request(0x40896c)` 在 `0x409c58` 附近用该路径与分发表字符串比较
3. 匹配 `"apply.cgi"` 后，`0x409c74` 读取分发表里的 handler 指针
4. `0x409c84` 调用 `0x406b60`
5. `0x406b60` 一进入就执行 refresh/redirect 相关早期逻辑，trace 在该 basic block 处终止并伴随 `SIGSEGV`

因此，本次崩溃的真正 source 是请求路径 `/apply.cgi`，而不是 body 中的 `upgrade_check_free.cgi`。

## 为什么判定为确认漏洞

- 请求路径 source 可解释: `VulPacket.json.request` 明确给出 `POST /apply.cgi`
- 入口与崩溃进程可解释: `main=0x4047d4` 精确命中 `usr_sbin_uhttpd.txt`
- URL 到 handler 的控制流可解释: `handle_request` 对 `"apply.cgi"` 的匹配与 `0x406b60` 的调用能和 trace 对齐
- 崩溃现象可解释: trace 在 `0x406b60` 后立即 `SIGSEGV`，控制台同步打印 `SIG 11`
- 替代解释不成立: 控制台没有出现 shell、外部命令、网络错误或子进程异常；异常发生在 `uhttpd` 主进程内部、且与 `/apply.cgi` handler 的直接分发一致

## 误报检查

- 这不是 body 参数误解析导致的假阳性；真正触发崩溃的是请求 URL `/apply.cgi` 对应的 handler 路径
- 这也不像环境错误:
  - 没有 `execve /bin/sh`
  - 没有外部命令失败
  - 没有子进程 `exit(127)` 或网络报错
- 当前仍无法把真正 faulting 指令精确缩小到 `0x406b60` 内的哪一条子操作，因为 trace 在该 basic block 起点后就直接截断为 `SIGSEGV`
- 但“`/apply.cgi` -> `handle_request` -> `0x406b60` -> SIGSEGV” 这条闭环已经足够支持确认漏洞

## 证据

- `VulPacket.json`: `POST /apply.cgi`
- `trace_summary.json`: `main_addr=0x4047d4` 命中 `usr_sbin_uhttpd.txt`
- `trace/usr_sbin_uhttpd.txt`:
  - `16: pc=0x4047d4`
  - `758: pc=0x40823c`
  - `761: pc=0x409c74`
  - `763: pc=0x406b60`
  - `764: --- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- `container.console.log`:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
