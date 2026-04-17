# 漏洞分析: fw-tew-818dru-v1-1.0.14.6 / id:000001,sig:11,src:000001,time:245477,execs:3686,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/httpd` `0x3ff50` `0x3faf4 -> strlen@plt`（调用时 `r0 == NULL`）
- Source位置: `/usr/sbin/httpd` `0x3ff50` `0x3ff98 -> 0xadfc`（以字符串常量 `WPSTimeout` 查询请求参数，返回 `NULL`）
- 漏洞二进制: `/usr/sbin/httpd`
- 漏洞类型: `NULL pointer dereference`
- 一句话根因: `restartWPSAutoPIN.cgi*` 处理函数在读取请求参数 `WPSTimeout` 后，没有判空就把返回值传给校验函数，后者立即执行 `strlen(NULL)` 并崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name = restartWPSAutoPIN.cgi*` -> 命中 `.data` 路由表项 `0x64c94 -> 0x3ff50`
  - `body.WPSTimeout` 缺失（`body` 为空） -> `r6 = adfc("WPSTimeout") = NULL`
  - `r6` -> `r0`（`0x3ffa0`）-> `0x3fae8` -> `strlen@plt`
- 执行顺序:
  1. `POST /restartWPSAutoPIN.cgi` 命中 `httpd` 中的 `restartWPSAutoPIN.cgi*` 路由，进入处理函数 `0x3ff50`。
  2. `0x3ff98` 以键 `"WPSTimeout"` 调用 `0xadfc` 从请求参数表中取值；由于本次 `VulPacket.json` 的 `body` 为空，`0xae40` 返回 `NULL`。
  3. `0x3ffa0` 直接把该 `NULL` 作为参数传入 `0x3fae8`，后者首个危险调用是 `0x3faf4: bl strlen@plt`，最终触发 `SIGSEGV (si_addr=NULL)`。

## Trace映射

- 入口二进制: `/usr/sbin/httpd`
- Main地址: `0xad28`
- 命中的入口trace: `trace/entry_trace.txt` 末尾显示入口进程自身以 `pc=0xb894` 后 `exit(0)` 收尾，说明崩溃不在入口主进程末尾。
- 子进程trace链: `trace/13_tb_log.txt` 从 `pc=0xad28` 开始执行 `httpd`，末尾落在 `0x3ff50 -> 0xadfc -> 0xae40 -> 0x3ffa0 -> 0x3fae8` 后触发 `SIGSEGV`。
- 关键pc地址:
  - `0xad28`: `/usr/sbin/httpd` ELF 入口
  - `0x3ff50`: `restartWPSAutoPIN.cgi*` 对应处理函数
  - `0x3ff98`: 加载 `"WPSTimeout"` 并调用 `0xadfc`
  - `0xadfc`: 基于全局 `hsearch_r` 参数表查询键值
  - `0xae40`: 查询 miss，保留 `r0 == NULL`
  - `0x3fae8`: 未判空校验函数
  - `0x3faf4`: `strlen@plt`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name = restartWPSAutoPIN.cgi*` 控制控制流进入 `0x3ff50`。
  - `body.WPSTimeout` 本应提供给该 handler；本次包里 `body` 为空，因此该字段缺失，导致 `adfc("WPSTimeout")` 返回 `NULL`。
- 哪个函数读取了source字段:
  - `0x3ff98` 把 rodata 常量 `0x5ecd0 ("WPSTimeout")` 传给 `0xadfc`。
  - `0xadfc` 通过 `hsearch_r@plt` 在请求参数哈希表中查找该键；`0xae40` 在未命中时直接返回 `NULL`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 这条崩溃链不是“恶意字符串内容”型，而是“缺少必需参数”型；没有观察到来自包内容的格式化/拼接，危险值就是查询失败得到的 `NULL`。
- 最终如何到达sink:
  - `adfc("WPSTimeout") -> r6 = NULL`
  - `0x3ffa0: mov r0, r6`
  - `0x3ffa4: bl 0x3fae8`
  - `0x3fae8` 一进入就 `mov r4, r0; bl strlen@plt`
  - 因 `r0 == NULL`，在 `strlen` 处发生空指针解引用并崩溃。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 不是仅凭容器日志下结论。`trace/13_tb_log.txt` 精确显示崩溃前执行序列为 `0x3ff98 -> 0xadfc -> 0xae40 -> 0x3ffa0 -> 0x3fae8 -> SIGSEGV`，与反汇编中“查询参数返回 `NULL` 后直接 `strlen`”完全一致。
  - `VulPacket.json` 的 `body` 确实为空，和 `"WPSTimeout"` 查找失败相互印证。
  - `.data` 路由表中存在 `0x64c94 ("restartWPSAutoPIN.cgi*") -> 0x3ff50` 的静态绑定，说明本次请求命中了该 handler，而不是其他背景线程偶发崩溃。
- 当前缺失的证据:
  - 没有原始 HTTP 报文文本，无法展示 `WPSTimeout=` 在报文级别“缺席”的原始编码形式；但 `VulPacket.json` 的空 `body` 与参数查找 miss 已足够确认漏洞。
- 对当前现象的替代解释:
  - 最合理替代解释是“参数解析子系统未初始化导致所有查找返回 `NULL`”。但这与本次 case 不符，因为同一请求已成功命中正确 handler，且 `adfc`/`hsearch_r` 的返回路径与“单个必需键缺失”完全一致，没有额外异常迹象。

## 证据

- 关键trace行:
  - `trace/13_tb_log.txt` 末尾: `pc=0x3ff98`, `pc=0xadfc`, `pc=0xae40`, `pc=0x3ffa0`, `pc=0x3fae8`, `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
  - `trace/entry_trace.txt` 末尾: `pc=0xb894` 后 `11 exit(0)`，说明入口主进程未在末尾崩溃。
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `Segmentation fault (core dumped)`
- 关键反编译证据:
  - `0x3ff98`: `ldr r0, [pc, #120]` -> 常量 `0x5ecd0 ("WPSTimeout")`; `bl 0xadfc`
  - `0xadfc`: 调用 `hsearch_r@plt` 查询键值；`0xae40` 在 miss 时返回 `NULL`
  - `0x3ffa0`: `mov r6, r0`; `bl 0x3fae8`
  - `0x3fae8`: 函数开头 `mov r4, r0`; `0x3faf4: bl strlen@plt`，无任何判空
  - `.data` 路由表 `0x72a40` 表项包含 `0x64c94 ("restartWPSAutoPIN.cgi*")` 和函数指针 `0x3ff50`
