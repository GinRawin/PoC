# 漏洞分析: t6-v3-v4.1.5cu.748-b20211015 / id:000003,sig:11,src:000000,time:70,execs:28,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/bin/lighttpd` `0x408950` `0x408b08`
- Source位置: `/bin/lighttpd` `0x430900` `0x430934`（Host/authority 类字段映射到 `request+0x20c`）；`/bin/lighttpd` `0x408950` `0x4089dc`（读取 `request+0x140`）
- 漏洞二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/T6/T6/debug/fs/bin/lighttpd`
- 漏洞类型: `NULL` 指针解引用导致的拒绝服务
- 一句话根因: `lighttpd` 的自定义请求处理函数在未校验 `request+0x20c` 是否为 `NULL` 的情况下，直接解引用并将其与 `"captive.apple.com"` 比较；攻击者只需让 URI 不命中白名单分支，同时让该 Host/authority 类指针保持为空，即可触发崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/phone"` -> `request->field_0x140->ptr`（路径类字符串，决定不命中 `.asp/.html/.htm/config.dat//login/login.cgi` 白名单）
  - `header.HOST="10.0.0.90"` 与 `header.host="||xhy"` -> `request->field_0x20c`（Host/authority 类 buffer 指针；该样本下实际保持为 `NULL`，精确字段名 unknown）
- 执行顺序:
  1. 入口二进制 `lighttpd` 解析 HTTP 请求并为 Host/authority 类字段保留 `request+0x20c` 这个槽位，相关映射指令位于 `0x430934`。
  2. 请求处理流程走到 `0x40d944 -> 0x408950`，先从 `request+0x140` 读取路径字符串；`/phone` 不匹配 `.asp`、`.html`、`.htm`、`config.dat`、`/login/login.cgi`，因此控制流落到 `0x408b00`。
  3. `0x408b04` 读取 `request+0x20c`，`0x408b08` 继续解引用 `*(request->field_0x20c)`；该指针为 `NULL`，因此立即触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/T6/T6/debug/fs/bin/lighttpd`
- Main地址: `0x405210`
- 命中的入口trace: `... -> 0x40d7f4 -> 0x40d814 -> 0x40d830 -> 0x40d854 -> 0x40d8f8 -> 0x40d944 -> 0x408950 -> 0x4089a4 -> 0x4089c0 -> 0x4089d8 -> 0x408b00 -> SIGSEGV`
- 子进程trace链: 未见必须跟踪的子进程；`entry_trace` 已直接覆盖崩溃路径
- 关键pc地址:
  - `0x40d944`: 调用崩溃函数 `0x408950`
  - `0x4089d8`: 读取 `request+0x140`
  - `0x408b00`: 开始读取 `request+0x20c`
  - `0x408b08`: 对 `NULL` 指针做第二次解引用，实际 fault site

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.prefix="/phone"` 控制 `request->field_0x140->ptr`，并决定 `0x408950` 中的白名单字符串比较全部失败。
  - `header.HOST`/`header.host` 控制 Host/authority 相关解析路径。二进制中 `0x430934` 明确把某个头字段绑定到结构体偏移 `0x20c`；同时字符串区存在 `duplicate Host-header -> 400`、`HTTP/1.1 but Host missing -> 400`、`Invalid Hostname -> 400`、`captive.apple.com`，与本样本的重复 Host 头和异常 host 值相吻合。
- 哪个函数读取了source字段:
  - `0x408950` 在 `0x4089dc/0x4089f0/0x408a18/0x408a40/0x408a68/0x408a90` 连续读取 `request+0x140` 指向的路径字符串。
  - `0x430900` 在 `0x430934` 使用偏移 `524 (0x20c)` 注册/映射 Host/authority 类请求字段。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 对 `request+0x20c` 的精确写入函数名 unknown，但 `0x430934` 已证明该字段是请求头解析阶段的目标槽位。
  - `0x408950` 直接消费 `request+0x140` 和 `request+0x20c`，未做空指针防护。
- 最终如何到达sink:
  - 攻击包中的 `POST /phone HTTP/1.1` 使 `request->field_0x140->ptr="/phone"`，不进入前面的白名单分支。
  - Host 相关头在该请求下没有形成可用的 `request->field_0x20c` buffer 对象。
  - 控制流到达 `0x408b00` 后，代码执行 `lw v0, 524(v0)` 再执行 `lw v0, 0(v0)`；第二条指令对 `NULL` 做解引用并崩溃。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - `entry_trace` 末尾给出了明确的 `SIGSEGV`，并且 fault site `0x408b08` 是稳定的空指针解引用，不是日志假象或超时。
  - 崩溃点位于 HTTP 请求处理路径内部，前驱基本块直接读取攻击者可控的路径和 Host/authority 类字段，属于可远程触发的输入驱动崩溃。
  - `container.console.log` 仅显示服务成功启动，没有其它环境异常；崩溃发生在收到请求后的处理路径上。
- 当前缺失的证据:
  - 还没有把 `request+0x20c` 的精确结构体字段名和最终赋值函数名恢复出来，因此报告中将该字段名记为 unknown / Host/authority 类 buffer。
- 对当前现象的替代解释:
  - 最合理的替代解释是“请求解析阶段因重复/异常 Host 头把 `request+0x20c` 留空，而后续自定义 captive portal 逻辑错误地假设该指针必非空”。这不是误报，而是更具体的根因解释。

## 证据

- 关键trace行:
  - `pc=0x40d944`
  - `pc=0x408950`
  - `pc=0x4089d8`
  - `pc=0x408b00`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- 关键容器日志行:
  - `2026-04-14 02:31:45: (log.c.97) server started`
- 关键反编译证据:
  - `0x4089d8: lw v0, 484(s8); 0x4089dc: lw v0, 320(v0); 0x4089e0: lw v0, 0(v0); 0x4089e4: beqz v0,0x408b00`
  - `0x4089fc-0x408aa8`: 将 `request+0x140->ptr` 与 `.asp`、`.html`、`.htm`、`config.dat`、`/login/login.cgi` 比较
  - `0x408b00: lw v0, 484(s8); 0x408b04: lw v0, 524(v0); 0x408b08: lw v0, 0(v0)`，这里对 `NULL` 进行解引用
  - `0x408b10-0x408b18`: 将该字段与字符串 `captive.apple.com` 比较，说明 `0x20c` 是 Host/authority 类字符串对象
  - `0x430934: li a2,524`，证明请求解析阶段存在把某个头字段映射到 `request+0x20c` 的逻辑
  - 二进制字符串: `.asp`、`.html`、`.htm`、`config.dat`、`/login/login.cgi`、`captive.apple.com`、`duplicate Host-header -> 400`、`HTTP/1.1 but Host missing -> 400`、`Invalid Hostname -> 400`
