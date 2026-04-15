# 漏洞分析: wnce4004-1.0.0.22.zip / id:000000,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd 0x404988 0x404f74`
- Source位置: `/usr/sbin/uhttpd 0x404988 0x404dd0`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `其他`
- 一句话根因: `handle_request()` 解析绝对路径请求时假定后续一定能在请求头里找到 `Host:`，当 `Host` 缺失时 `s4` 维持为 `NULL`，随后在 `0x404f74` 把这个空指针传给 `strstr()`，触发空指针解引用。
- 数据包字段 -> 变量赋值:
  - `request.method=GET` -> 首行缓冲区 `sp+0x2c` -> `strcasecmp(...,"get")` at `0x404e80`
  - `request.prefix=/` + `request.handler_name=WLG_adv.htm` -> 原始 URL `/WLG_adv.htm` -> `strsep` 第二个 token -> `arg_20h` at `0x404a00/0x404a18` -> 首字符检查 at `0x404f18/0x404f24`
  - `header.Host` 缺失 -> header loop 中 `strncasecmp(line,"Host:",5)` at `0x404dd0` 始终不匹配 -> `s4` 保持为 `0`（初始化于 `0x404b2c`）
  - `query.test/query.125/query.200` -> 原始请求行里的查询串；本次崩溃路径没有依赖这些参数进入 sink
- 执行顺序:
  1. `uhttpd` 的 `handle_request()` 通过 `fgets` 读取请求首行，并用 `strsep` 拆出 method 和 URL token。
  2. URL token `/WLG_adv.htm?...` 被放入 `arg_20h`，代码在 `0x404f24` 检查其首字符是 `/`。
  3. 同一函数继续逐行读取 header，并在 `0x404dd0` 用 `strncasecmp(...,"Host:",5)` 查找 `Host:`；由于该请求没有 `Host`，保存主机名的 `s4` 一直保持 `NULL`。
  4. 绝对路径分支跳到 `0x404f6c`，在 `0x404f74` 调用 `strstr(s4, "mywifiext.net")`，其中 `a0=s4=NULL`。
  5. `strstr()` 里发生空指针解引用，trace 在 `0x404f18 -> 0x404f6c` 后接 `SIGSEGV`，容器日志记录 `SIG 11`。

## 原始请求与 URL 还原

- `VulPacket.json.request.method = GET`
- `VulPacket.json.request.prefix = /`
- `VulPacket.json.request.handler_name = WLG_adv.htm`
- 因此原始请求 URL 应还原为 `/WLG_adv.htm`
- `VulPacket.json.body.test/body.125/body.200` 不是 URL；结合 `packet_1.request.raw` 可知它们实际出现在查询串里：`GET /WLG_adv.htm?test=3&125=...&200=... HTTP/1.1`
- 原始请求头只有 `Cookie: uid=xhyxhy` 和 `Content-Length: 0`，没有 `Host:` 头

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 给出的 `main` 地址: `0x403df4`
- `trace_summary.json` 自动匹配: `usr_sbin_uhttpd.txt`，匹配点 `pc=0x403df4`
- 命中的入口 trace: `trace/usr_sbin_uhttpd.txt`
- 同一 trace 内关键执行序列:
  - `pc=0x404988` 进入 `handle_request()`
  - `pc=0x404dd8 -> 0x404e50` 表示 `Host:` 解析分支未命中并继续读 header
  - `pc=0x404eec -> 0x404f18 -> 0x404f6c`
  - 随后 `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- 相关子进程 trace (`11_tb_log.txt`, `13_tb_log.txt`, `15_tb_log.txt`, `23_tb_log.txt`) 只反映固件后台任务，与当前崩溃链无关；崩溃发生在入口 `uhttpd` 进程自身

## 关键地址与数据流

### 1. 首行解析

- `0x4049e4`: `fgets(sp+0x2c, 0x2710, ...)` 读取请求首行
- `0x404a04`: 第一次 `strsep` 后把 token 指针写回 `arg_20h`
- `0x404a44`, `0x404a84`: 继续拆分首行剩余 token
- `0x404f18`: 读取 `arg_20h`
- `0x404f24`: 若首字符为 `/`，跳转到 `0x404f6c`

这里的 `arg_20h` 对应原始 URL token。对于本包，它来自请求行里的 `/WLG_adv.htm?test=3&125=...&200=...`。

### 2. Host 头解析

- `0x404b2c`: `move s4, zero`，把 Host 指针初始化为 `NULL`
- `0x404dd0`: `strncasecmp(s1, "Host:", 5)` 检查当前 header 行是不是 `Host:`
- `0x404dd8`: 若不匹配则直接回到 `0x404e50` 继续 `fgets` 读取下一行
- `0x404e00`: 只有匹配 `Host:` 时才会执行 `s4 = s0 + strspn(...)`，把 `s4` 设为 Host 值起始位置

本次请求里没有 `Host:`，所以 trace 命中了 `0x404dd8 -> 0x404e50` 的“不匹配继续读 header”分支，`s4` 没有被赋值。

### 3. Sink

- `0x404f6c`: 进入绝对路径处理分支
- `0x404f74`: 调用 `strstr(a0=s4, a1="mywifiext.net")`
- `0x404f90`: 若前一次没有命中，还会继续检查 `"mywifiext.com"`

由于 `s4 == NULL`，第一个 `strstr()` 已经足以触发空指针解引用。

## 关键证据

- `packet_1.request.raw`:
  - `GET /WLG_adv.htm?test=3&125=...&200=... HTTP/1.1`
  - `Cookie: uid=xhyxhy`
  - `Content-Length: 0`
  - 没有 `Host:` 行
- `trace/usr_sbin_uhttpd.txt`:
  - `pc=0x403df4` 命中 `uhttpd` 的 `main`
  - `pc=0x404988` 进入 `handle_request`
  - `pc=0x404dd8` 后立即回到 `pc=0x404e50`，对应 `Host:` 检查未命中
  - `pc=0x404eec`
  - `pc=0x404f18`
  - `pc=0x404f6c`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- `container.console.log`:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
- 反汇编:
  - `0x404b2c: move s4, zero`
  - `0x404dc8: "Host:"`
  - `0x404dd0: strncasecmp(..., "Host:", 5)`
  - `0x404e00: addu s4, s0, v0`
  - `0x404f70: "mywifiext.net"`
  - `0x404f74: jalr t9` with `a0=s4`

## 误报检查

- 这不是单纯环境噪声。崩溃发生在入口 HTTP 进程自身，且 trace、反汇编、原始请求三者能闭合出 `缺失 Host 头 -> s4 为 NULL -> strstr(NULL, ...) -> SIGSEGV` 的链条。
- 这也不是由 `body.test/125/200` 驱动的假象。`Content-Length: 0`，这些值仅出现在查询串里，而当前崩溃链依赖的是 `header.Host` 的缺失。
- 不需要额外 shell、子进程、外部命令或环境失败来解释该现象。
