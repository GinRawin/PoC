## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `fcn.00439b28 @ 0x439b28` `0x439ba8`
- Source位置: `/usr/sbin/uhttpd` `fcn.00439b28 @ 0x439b28` `0x439b5c`, `/usr/sbin/uhttpd` `fcn.00439b28 @ 0x439b28` `0x439b7c`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `wlacl_add` handler 把 `body.adr` 与超长 `body.device` 用 `sprintf("%s %s")` 拼进仅 260 字节的栈缓冲区 `sp+0x18`，覆盖保存的返回地址，函数返回时跳到 `0x32323232` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name -> /apply.cgi?pls_wait.html`，定义原始请求 URL
  - `body.submit_flag="wlacl_add" -> sym.cgi_setobject @ 0x40b95c` 选中 `wlacl_add` 对应 handler `fcn.00439b28`
  - `body.device -> cgi_value("device") @ 0x439b5c -> v0 -> sprintf @ 0x439ba8` 的第 2 个 `%s`
  - `body.adr -> cgi_value("adr") @ 0x439b7c -> s1 -> sprintf @ 0x439ba8` 的第 1 个 `%s`
  - `sprintf` 输出 -> 栈缓冲区 `sp+0x18`，可用空间到保存的 `s0` 仅 `0x104` 字节
  - 当前样本写入长度 `len(adr)=32` + 空格 `1` + `len(device)=256` + `NUL 1` = `290` 字节，超出缓冲区 `30` 字节
  - 溢出数据中的 `'2'` 覆盖保存返回地址 -> 函数尾声经 `0x439bfc/0x439c00` 返回时跳转到 `0x32323232`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?pls_wait.html`。
  2. `sym.cgi_setobject @ 0x40b95c` 在 `0x40b9ac` 读取 `submit_flag`，匹配到 `wlacl_add`，分发到 `fcn.00439b28`。
  3. `fcn.00439b28` 在 `0x439b5c` 读取 `device`，在 `0x439b7c` 读取 `adr`。
  4. `0x439ba8` 调用 `sprintf(sp+0x18, "%s %s", adr, device)`，把 290 字节写进 260 字节栈缓冲区，覆盖保存寄存器和返回地址。
  5. 函数继续执行 `add_items("wlacl", ...)` 和 `nvram_set("wl_acl_num", ...)`，但返回时使用已被 `'2'` 覆盖的返回地址，最终触发 `SIGSEGV si_addr=0x32323232`。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?pls_wait.html`
- handler 来源: `VulPacket.json -> packet_1.request.prefix` 与 `packet_1.request.handler_name`

body 中最关键的字段是：

- `submit_flag = "wlacl_add"`
- `device`，长度 `256`
- `adr`，长度 `32`

这些都是请求体参数，不是原始 URL；真正让程序进入漏洞路径的是 `request` 指定的 `/apply.cgi?pls_wait.html` 与 `body.submit_flag = wlacl_add` 的组合。

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main`: `0x4047d4`
- `trace_summary.json` 将入口 trace 精确匹配为 `trace/usr_sbin_uhttpd.txt`
- 关键 trace:
  - `pc=0x40b95c`
  - `pc=0x40b9e4`
  - `pc=0x40ba44`
  - `pc=0x439b28`
  - `pc=0x439b64`
  - `pc=0x439b94`
  - `pc=0x439bbc`
  - `pc=0x439bd8`
  - `pc=0x439bf4`
  - `pc=0x439bfc`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`

这条 trace 没有 fork/execve，说明崩溃发生在 `uhttpd` 主进程内部。

## 关键数据流

### 1. `submit_flag` 正常分发到 `wlacl_add`

`sym.cgi_setobject @ 0x40b95c` 的 trace 为：

- `0x40b9ac`: `cgi_value("submit_flag")`
- `0x40b9e4`: 命中非空 `submit_flag`
- `0x40ba44` 开始遍历 action 表
- `0x439b28`: 进入 `wlacl_add` 对应处理函数

因此该样本不是缺字段误报，而是确实进入了具体 handler。

### 2. handler 两次读取用户输入

`fcn.00439b28 @ 0x439b28` 的关键反汇编：

- `0x439b48` 取 `sym.cgi_value`
- `0x439b54`: key 为 `"device"`
- `0x439b5c`: `cgi_value("device")`
- `0x439b70`: key 为 `"adr"`
- `0x439b7c`: `cgi_value("adr")`

随后：

- `0x439b84`: 若 `adr` 为空则跳过
- `0x439b8c`: 若 `device` 为空则跳过

当前样本中两者都存在，因此继续进入拼接路径。

### 3. 栈缓冲区溢出发生在第一次 `sprintf`

同一函数中：

- `0x439b98`: `s0 = sp + 0x18`
- `0x439b9c`: format 为 `"%s %s"`
- `0x439ba0`: `a3 = v0`，即 `device`
- `0x439ba4`: `a2 = s1`，即 `adr`
- `0x439ba8`: `sprintf(s0, "%s %s", adr, device)`

栈布局显示：

- 缓冲区起点: `sp + 0x18`
- 保存的 `s0`: `sp + 0x11c`
- 因此缓冲区可用空间只有 `0x11c - 0x18 = 0x104 = 260` 字节

当前输入长度：

- `adr = 32`
- `device = 256`
- 拼接结果 `"adr + ' ' + device + '\\0'" = 290` 字节

因此第一次 `sprintf` 必然越界 `30` 字节，覆盖保存的 `s0/s1/ra`。

### 4. 为什么 crash 出现在函数尾部

溢出发生后，函数还会继续执行：

- `0x439bbc`: 调 `sym.add_items("wlacl", sp+0x18)`
- `0x439bd8`: `sprintf(sp+0x18, "%d", idx)`
- `0x439bf4`: `nvram_set("wl_acl_num", sp+0x18)`

但这些操作只重写了缓冲区开头，没有恢复已经被覆盖的高地址保存区。随后：

- `0x439bfc`: 开始函数尾声
- `0x439c00`: 取回保存的 `ra`
- trace 紧接着报 `si_addr=0x32323232`

这与“返回地址被 `'2'` 覆盖，`jr ra` 跳到 `0x32323232`”完全一致。

## 补充反编译证据

### `sym.add_items @ 0x40ccfc`

`0x439bbc` 调到的 `sym.add_items` 并不是漏洞本体。它的逻辑是：

- `0x40cd48`: `sprintf(sp+0x18, "%s%d", prefix, idx)`，这里 prefix 是常量 `"wlacl"`
- `0x40cd64`: `nvram_get("wlacl%d")`
- `0x40cd88`: `nvram_set("wlacl%d", user_string)`

这个函数负责把前面已经拼好的字符串插入第一个空的 `wlacl%d` 项。真正破坏栈的是进入它之前的 `sprintf("%s %s")`。

## Trace / Console 证据

### Trace

- `usr_sbin_uhttpd.txt:683` 命中 `pc=0x40b95c`
- `usr_sbin_uhttpd.txt:717` 命中 `pc=0x439bfc`
- `usr_sbin_uhttpd.txt:718` 出现 `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x32323232} ---`

### Console

容器日志中的：

- `wlacl1=Unknown`
- `[GreenHouseQEMU] SIGSEGV CAUGHT!`

与 handler 里对 `wlacl` 项目的写入逻辑和最终崩溃现象一致。

## 为什么这是确认漏洞

这个样本已经具备完整闭环：

- 可解释的 source:
  - `cgi_value("device") @ 0x439b5c`
  - `cgi_value("adr") @ 0x439b7c`
- 可解释的 sink:
  - `sprintf(sp+0x18, "%s %s", adr, device) @ 0x439ba8`
- 可解释的数据流:
  - `body.adr/body.device -> cgi_value -> sprintf varargs -> 栈缓冲区`
- 与 trace/崩溃一致的后果:
  - 返回地址被 `0x32` 覆盖
  - epilogue 返回到 `0x32323232`
  - `SIGSEGV`

因此这不是环境噪声，也不是仅有现象没有根因的可疑样本，而是确定的栈溢出漏洞。
