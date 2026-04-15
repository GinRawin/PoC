# 漏洞分析: xwn5001-0.4.1.1.zip / id:000004,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `0x4355d8` `0x43562c`
- Source位置: `/usr/sbin/uhttpd` `0x4355d8` `0x435618`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `submit_flag=ether` 会进入 ether 配置 handler `0x4355d8`，该函数读取 `body.device_name` 后未经空指针检查就执行 `strcpy(obj.netbiosname, value)`，当请求缺失 `device_name` 时直接触发 `SIGSEGV(NULL)`。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`，`request.prefix=/`，`request.handler_name=apply.cgi?upgrade_check_free.cgi` -> 原始请求 URL `/apply.cgi?upgrade_check_free.cgi`
  - `body.submit_flag="ether"` -> `sym.cgi_setobject` 中 `cgi_value("submit_flag") @ 0x40b9ac` -> `s1` -> 与分发表字符串 `"ether"` 比较成功 -> 表项 `0x471904` -> handler 指针 `0x4355d8`
  - `body.device_name` 缺失 -> `cgi_value("device_name") @ 0x435618` 返回 `v0=NULL`
  - `v0(NULL)` -> `strcpy` 的 `arg#1/src`，`obj.netbiosname` -> `strcpy` 的 `arg#0/dst`，调用点 `0x43562c`
  - `body.netbiosname="22222222"` 只是请求体参数，当前崩溃路径里并未被 `0x4355d8` 读取；该 handler 实际读取的是 `device_name`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?upgrade_check_free.cgi`
  2. 请求进入 CGI POST 处理路径 `0x406c28 -> 0x406eb0 -> sym.cgi_setobject(0x40b95c)`
  3. `sym.cgi_setobject` 在 `0x40b9ac` 读取 `submit_flag`，与分发表比较后命中 `"ether"`，通过表项 `0x471904` 跳转到 handler `0x4355d8`
  4. ether handler 在 `0x435618` 读取 `device_name`，但样本没有提供该字段，因此返回 `NULL`
  5. handler 在 `0x43562c` 执行 `strcpy(obj.netbiosname, NULL)`，trace 紧跟着在 `0x435620` 后报 `SIGSEGV {si_addr=NULL}`

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- 依据: `VulPacket.json` 中 `packet_1.request.prefix="/"` 与 `packet_1.request.handler_name="apply.cgi?upgrade_check_free.cgi"`
- 请求体关键参数:
  - `submit_flag=ether`
  - `netbiosname=22222222`
  - 不存在 `device_name`

这里要严格区分层次: 原始 URL 来自 `request`，不是来自 `body`。虽然 body 中存在 `netbiosname` 等参数，但它们只是请求体字段，不定义访问的 handler。

## 入口二进制与 Trace 映射

- 固件入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 已恢复 `main=0x4047d4`
- `trace_summary.json` 将入口 trace 映射为 `trace/usr_sbin_uhttpd.txt`
- 当前 case 的关键 trace 片段:
  - `pc=0x406c28`
  - `pc=0x406eb0`
  - `pc=0x40b95c`
  - `pc=0x40b9ac` 对应 `cgi_value("submit_flag")`
  - `pc=0x40ba44 -> 0x40ba10` 对应分发表匹配与取 handler 指针
  - `pc=0x4355d8`
  - `pc=0x40b514` 对应 `cgi_value` 返回
  - `pc=0x435620`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

没有看到子进程 `fork/execve` 证据，漏洞发生在 `uhttpd` 入口进程内部。

## 关键静态证据

### 1. `submit_flag` 分发表确实把 `"ether"` 映射到 `0x4355d8`

`sym.cgi_setobject @ 0x40b95c` 的核心逻辑是:

- `0x40b9ac`: `cgi_value("submit_flag")`
- `0x40b9e4`: 调用 `0x40adcc`
- `0x40adcc`: 仅返回 `0`，不会改写 `submit_flag`
- `0x40b9f8`: 初始化分发表基址 `s0 = 0x4718b0`
- `0x40ba44`: 取当前表项字符串
- `0x40ba4c`: `strcmp(entry_name, submit_flag)`
- `0x40ba10`: 读取 action id
- `0x40ba20`: 读取 handler 指针
- `0x40ba30`: 跳转执行 handler

手工解码分发表 `0x4718f8` 附近内容:

- `0x4718f8 -> { "pppoa", 0x2, 0x43616c }`
- `0x471904 -> { "ether", 0x2, 0x4355d8 }`
- `0x471910 -> { "mulpppoe", 0x2, 0x435a90 }`

因此这个样本的 `submit_flag="ether"` 最终进入 `0x4355d8`，不是误命中其它分支。

### 2. `0x4355d8` 读取的是 `device_name`，然后直接 `strcpy`

`0x4355d8` 附近反汇编可解释为:

- `0x435604`: 加载 `sym.cgi_value`
- `0x435610`: 参数字符串为 `"device_name"`
- `0x435618`: 调用 `cgi_value("device_name", req, ...)`
- `0x435624`: 加载 `strcpy`
- `0x435628`: 目的地址为全局 `obj.netbiosname`
- `0x43562c`: 调用 `strcpy(obj.netbiosname, v0)`

同一区域字符串还能看到:

- `0x45d2ec -> "device_name"`
- `0x459770 -> "netbiosname"`
- `0x45d2f8 -> "config_ether: change netbios:%s -----------\n"`
- `0x45d328 -> "http://%s/welcomeok.htm"`

这说明 `0x4355d8` 就是 ether 配置相关逻辑，且它把 `device_name` 复制进名为 `netbiosname` 的全局缓冲区。

## Source -> Variable -> Sink 数据流

本 case 的可解释数据流是:

1. `body.submit_flag="ether"` 被 `sym.cgi_setobject` 在 `0x40b9ac` 读取。
2. 该值经过分发表字符串比较，命中 `"ether"` 表项 `0x471904`。
3. `sym.cgi_setobject` 通过表项中的函数指针调用 ether handler `0x4355d8`。
4. ether handler 在 `0x435618` 读取 `body.device_name`。
5. 当前请求没有 `device_name`，所以 `cgi_value` 返回 `NULL`。
6. `NULL` 被直接放进 `strcpy` 的 source 参数，在 `0x43562c` 调用时解引用，导致 `SIGSEGV(NULL)`。

这条链条与 trace 完全一致:

- `0x40b95c -> 0x40b9ac -> 0x40ba44/0x40ba10 -> 0x4355d8 -> 0x40b514 -> 0x435620 -> SIGSEGV(NULL)`

## Trace / Console 证据

### Trace 证据

- `trace/usr_sbin_uhttpd.txt` 清楚显示控制流进入:
  - POST 解析路径 `0x406c28`
  - `sym.cgi_setobject` `0x40b95c`
  - 分发表匹配路径 `0x40ba44`, `0x40ba10`
  - ether handler `0x4355d8`
  - `cgi_value` 返回后落回 `0x435620`
  - 随后立即 `SIGSEGV {si_addr=NULL}`

`si_addr=NULL` 与 `strcpy(dst, NULL)` 的静态语义完全吻合。

### Console 证据

`container.console.log` 只显示:

- `[GreenHouseQEMU] SIGSEGV CAUGHT!`
- `[GreenHouseQEMU] SIG 11`

没有 shell、子进程、环境命令失败等噪声证据，因此这不是命令执行路径上的偶发失败，而是 `uhttpd` 内部同步崩溃。

## 结论

这是一个可确认的参数校验缺失漏洞，不是误报，也不是“证据不足”。

确认依据有四个关键点:

1. 原始请求 URL 可由 `request` 唯一确定为 `/apply.cgi?upgrade_check_free.cgi`
2. `submit_flag="ether"` 到 ether handler `0x4355d8` 的分发表映射已经静态坐实
3. handler 内部存在精确 source `cgi_value("device_name") @ 0x435618` 和精确 sink `strcpy(...) @ 0x43562c`
4. trace 末尾的 `SIGSEGV(NULL)` 与 `strcpy` 使用空 source 指针的行为完全一致

根因不是 `body.netbiosname` 太长，也不是其它超长字段触发溢出；真正触发崩溃的是:

- 请求通过 `submit_flag=ether` 进入 ether 配置 handler
- 但请求缺失 handler 强依赖的 `device_name`
- 程序未检查 `cgi_value` 返回值是否为空
- 直接把 `NULL` 传给 `strcpy`

