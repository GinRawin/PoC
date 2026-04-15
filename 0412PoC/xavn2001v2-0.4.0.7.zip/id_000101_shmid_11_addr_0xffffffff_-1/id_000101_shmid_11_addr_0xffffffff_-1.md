## 摘要

- 判定: 确认漏洞
- Sink位置: /usr/sbin/uhttpd 0x439d50 0x439e14
- Source位置: /usr/sbin/uhttpd 0x439d50 0x439dc8
- 漏洞二进制: /usr/sbin/uhttpd
- 漏洞类型: 命令注入
- 一句话根因: `diag` 处理函数把未过滤的 `body.pingName` 直接拼进 `ping -c 3 %s > /tmp/ping_res`，再通过 `system()` 交给 `/bin/sh -c` 执行。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=apply.cgi` -> 原始请求 URL 为 `/apply.cgi`
  - `body.submit_flag=diag` -> `cgi_setobject(0x40b95c)` 选择诊断处理路径
  - `body.diag_type=1` -> `atoi()` 结果为 `1`，进入 ping 分支
  - `body.pingName` -> `s1` (`cgi_value("pingName")`) -> `sprintf` arg#3 at `0x439df8` -> 命令缓冲区 `sp+0x18`
- 执行顺序:
  1. `POST /apply.cgi` 进入 `uhttpd` 的 `apply.cgi` 分发逻辑。
  2. `cgi_setobject` 根据 `body.submit_flag=diag` 转入 `diag` 处理函数 `0x439d50`。
  3. `0x439d8c` 读取 `diag_type`，值为 `1`；`0x439dc8` 读取 `pingName`。
  4. `0x439e04` 调用 `sprintf(sp+0x18, "ping -c 3 %s > /tmp/ping_res", pingName)`。
  5. `0x439e14` 调用 `system(sp+0x18)`，trace 记录到 `/bin/sh -c` 执行完整命令，随后出现与攻击字符串一致的崩溃地址 `0x32323232`。

## 请求与入口

- `VulPacket.json.request` 显示原始请求为 `POST /apply.cgi`。
- `body.show_traffic=pls_wait.html` 只是请求体参数，不是 URL。
- `trace_summary.json` 将入口二进制匹配为 `/usr/sbin/uhttpd`，`main=0x4047d4`，命中 trace 为 `trace/usr_sbin_uhttpd.txt`。

## 关键数据流

- `0x439d78` / `0x439d8c`：`cgi_value("diag_type")`
- `0x439d9c`：`atoi(diag_type)`，值为 `1`
- `0x439dbc` / `0x439dc8`：`cgi_value("pingName")`
- `0x439dfc` / `0x439e04`：`sprintf(sp+0x18, "ping -c 3 %s > /tmp/ping_res", pingName)`
- `0x439e10` / `0x439e14`：`system(sp+0x18)`
- 该链条已经满足 `source -> variable -> sink` 闭环，不需要依赖崩溃才能确认命令注入。

## Trace / console 证据

- `trace/usr_sbin_uhttpd.txt:711-719`：
  - 进入 `0x439d50`
  - 在 `0x439ddc`、`0x439df0`、`0x439e0c` 继续构造并准备执行命令
- `trace/usr_sbin_uhttpd.txt:720-723`：
  - `15 fork() = 18`
  - `18 execve("/bin/sh", {"sh","-c","ping -c 3 2222... > /tmp/ping_res", NULL}) = 0`
- `container.console.log`：
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /bin/ping`
  - `ping: 2222...: Unknown host`
- `trace/usr_sbin_uhttpd.txt:727`：
  - `SIGSEGV {si_addr=0x32323232}`

## 结论

- 这是确认的命令注入，不是误报。
- 决定性证据不是后续 `SIGSEGV`，而是：
  - `pingName` 被 `cgi_value` 读取
  - 进入 `sprintf("ping -c 3 %s > /tmp/ping_res", pingName)`
  - 再被 `system()` 通过 `/bin/sh -c` 执行
- 当前样本使用纯数字长字符串也已经证明了命令模板可控；若改为 shell 元字符，命令将被同一路径解释执行。
