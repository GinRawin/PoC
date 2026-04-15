## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `fcn.00438cdc @ 0x438cdc` `0x438d5c`
- Source位置: `/usr/sbin/uhttpd` `fcn.00438cdc @ 0x438cdc` `0x438d18`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `wlan_brs` handler 读取 `body.wl_ssid` 时没有检查返回值，样本又缺少该字段，结果把 `NULL` 直接传给 `nvram_set`，在 `uhttpd` 内部触发空指针解引用崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix + request.handler_name -> /apply.cgi`，定义原始请求 URL
  - `body.submit_flag="wlan_brs" -> sym.cgi_setobject @ 0x40b95c` 分发到 `fcn.00438cdc`
  - `body.wl_ssid` 缺失 -> `cgi_value("wl_ssid") @ 0x438d18` 返回 `NULL`
  - `cgi_value("wl_ssid")==NULL -> delay slot 0x438d1c 把 NULL 写入 s0`
  - `sp+0x18` 上的格式化 key -> `nvram_set @ 0x438d5c` arg#0
  - `s0(NULL) -> nvram_set @ 0x438d5c` arg#1 -> NULL dereference
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi`。
  2. `sym.cgi_setobject @ 0x40b95c` 在 `0x40b9ac` 读到 `submit_flag=wlan_brs`，分发到 `fcn.00438cdc`。
  3. `fcn.00438cdc` 在 `0x438d18` 调用 `cgi_value("wl_ssid")`，但请求体没有 `wl_ssid`，返回 `NULL`。
  4. 该函数随后在 `0x438d48` 生成一个 NVRAM key，到 `0x438d5c` 直接执行 `nvram_set(key, NULL)`。
  5. `nvram_set` 内部对 NULL value 解引用，trace 在 `0x438d50` 后立刻报 `SIGSEGV si_addr=NULL`。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi`
- handler 来源: `VulPacket.json -> packet_1.request.prefix` 与 `packet_1.request.handler_name`

关键 body 字段：

- `submit_flag = "wlan_brs"`
- `mode = "1"`

需要特别说明：

- 该样本真正访问的 URL 是 `/apply.cgi`
- body 中那些看起来像配置项的长值只是参数
- 与漏洞直接相关的关键点不是某个超长字段，而是 `wl_ssid` 这个字段根本缺失

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `main`: `0x4047d4`
- `trace_summary.json` 将入口 trace 匹配为 `trace/usr_sbin_uhttpd.txt`
- 关键 trace:
  - `pc=0x40b95c`
  - `pc=0x40b9e4`
  - `pc=0x40ba44`
  - `pc=0x438cdc`
  - `pc=0x438d20`
  - `pc=0x438d50`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

没有 fork/execve，说明崩溃发生在 `uhttpd` 主进程内部。

## 关键数据流

### 1. `submit_flag=wlan_brs` 进入专门 handler

入口 trace 显示：

- `0x40b95c`: 进入 `sym.cgi_setobject`
- `0x40b9e4`: `submit_flag` 非空
- `0x40ba44` 之后命中 action 表
- `0x438cdc`: 进入 `wlan_brs` 对应处理函数

因此这个 case 不是随机崩溃，而是稳定到达了 `wlan_brs` 逻辑。

### 2. handler 首先读取 `wl_ssid`

`fcn.00438cdc @ 0x438cdc` 的关键反汇编：

- `0x438d04`: 取 `sym.cgi_value`
- `0x438d10`: key 为 `"wl_ssid"`，对应文件偏移 `0x588d4`
- `0x438d18`: `cgi_value("wl_ssid")`
- `0x438d1c`: delay slot `move s0, v0`

当前请求体中并没有 `wl_ssid`，因此这次 `cgi_value` 返回 `NULL`，`s0` 也随之变成 `NULL`。

### 3. 代码没有判空，直接把 NULL 交给 `nvram_set`

后续同一函数里：

- `0x438d30`: `s1 = sp + 0x18`
- `0x438d38`: `sprintf`
- `0x438d40`: format 为 `"%s%s"`，在栈上拼出目标 NVRAM key
- `0x438d50`: 回到调用点
- `0x438d58`: 取 `nvram_set`
- `0x438d5c`: `jalr t9`
- `0x438d60`: delay slot `move a1, s0`

由于 `s0 == NULL`，这条调用等价于：

```c
nvram_set(formatted_key, NULL);
```

trace 在 `0x438d50` 后立即报：

- `SIGSEGV`
- `si_addr = NULL`

这与空指针 value 传入 `nvram_set` 完全一致。

## 为什么不是长字符串溢出

虽然请求体里有多个 128/256 字节字段，但这条崩溃路径并没有把它们复制进局部缓冲区。当前 trace 只覆盖到：

1. 读取 `wl_ssid`
2. 生成 key
3. `nvram_set(key, s0)`

而 `s0` 来自缺失字段的 `NULL`，不是某个超长字符串。因此这次的真实根因是空指针使用，不是溢出。

## Trace / Console 证据

### Trace

- `usr_sbin_uhttpd.txt:670` 命中 `pc=0x40b95c`
- `usr_sbin_uhttpd.txt:693` 命中 `pc=0x438d20`
- `usr_sbin_uhttpd.txt:694` 命中 `pc=0x438d50`
- `usr_sbin_uhttpd.txt:695` 报 `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

### Console

容器日志中只有：

- `[GreenHouseQEMU] SIGSEGV CAUGHT!`
- `[GreenHouseQEMU] SIG 11`

虽然日志本身没有打印字段名，但它与 trace 中的 NULL deref 完全一致。

## 为什么这是确认漏洞

这个样本已经具备完整闭环：

- 可解释的 source:
  - `cgi_value("wl_ssid") @ 0x438d18`
- 可解释的 sink:
  - `nvram_set(..., s0) @ 0x438d5c`
- 可解释的数据流:
  - `body.wl_ssid 缺失 -> cgi_value 返回 NULL -> s0 -> nvram_set value`
- 与 trace/崩溃一致的后果:
  - `si_addr=NULL`
  - 主进程内直接 `SIGSEGV`

因此这不是环境噪声，也不是“只有现象没有根因”的可疑样本，而是明确的空指针解引用漏洞。
