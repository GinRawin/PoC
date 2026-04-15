## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `0x406b60` `0x406b90`
- Source位置: `/usr/sbin/uhttpd` `0x40b95c` `0x40b9ac`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 参数校验缺失
- 一句话根因: `/apply.cgi` 路径上 `submit_flag` 被取出后未命中任何已知分支，`handle_request` 先清零的 `refresh_url/refresh_time/refresh_top` 没有被重新初始化，随后 `0x406b60` 无保护解引用 `*obj.refresh_url`，触发 `NULL` 地址崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method = POST`
  - `request.prefix + request.handler_name -> /apply.cgi`，定义原始请求 URL
  - `body.submit_flag = "ﾌﾃ"` -> `fcn.00406c28` 解析后的键值表 `sp+0x18` -> `sym.cgi_setobject(0x40b9ac)` 调用 `cgi_value("submit_flag", parsed_pairs, count)` -> 返回指针 `s1`
  - `s1("ﾌﾃ")` -> `sym.cgi_setobject` 的字符串比较链 `0x40ba44 .. 0x40bb90` -> 所有已知 action 分支均未命中
  - `未命中分支` -> `obj.refresh_time @ 0x474690` 未在 `0x40bba0` 写入
  - `当前路径未经过 sym.cgi_func` -> `obj.refresh_url @ 0x474694` 未在 `0x40bec8/0x40bed4` 写入
  - `obj.refresh_url == NULL` -> `fcn.00406b60` 的 `lw v0, (v0)` at `0x406b90`
- 执行顺序:
  1. `uhttpd` 接收 `POST /apply.cgi`。
  2. `sym.handle_request` 在 `0x409530/0x40953c/0x409544` 先把 `refresh_top`、`refresh_url`、`refresh_time` 三个全局槽位清零。
  3. 预处理函数 `fcn.00406c28` 读取并解析请求体，进入 `fcn.00406d14` 的键值解析循环，再在 `0x406eb8` 调用 `sym.cgi_setobject`。
  4. `sym.cgi_setobject` 在 `0x40b9ac` 读取 `submit_flag`，但 `"ﾌﾃ"` 未匹配任何已知分支；trace 走到 `0x40bbac`，没有执行设置 `refresh_time` 的 `0x40bba0`。
  5. `handle_request` 随后继续调用页面回调，trace 显示 `0x409c74 -> 0x409c80 -> 0x406b60`。
  6. `fcn.00406b60` 在函数开头二次解引用 `obj.refresh_url`；由于该槽位仍为 `NULL`，在 `0x406b90` 访问 `NULL` 触发 `SIGSEGV`。

## 原始请求

- 请求方法来自 `VulPacket.json.packet_1.request.method`: `POST`
- 请求路径来自 `VulPacket.json.packet_1.request.prefix` + `handler_name`: `/apply.cgi`
- `body.submit_flag = "ﾌﾃ"` 是请求体参数，不是 URL；本样本里真正影响崩溃闭环的字段只有这个 body 参数有直接证据。

## 入口二进制与 Trace 映射

- `firmware_context.json` 给出的唯一入口二进制是 `/usr/sbin/uhttpd`
- `binary_summary.json` 记录 `main = 0x4047d4`
- `trace_summary.json` 将入口 trace 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 片段:
  - `pc=0x406c28`
  - `pc=0x406eb0`
  - `pc=0x40b95c`
  - `pc=0x40bbac`
  - `pc=0x409b54`
  - `pc=0x409c74`
  - `pc=0x409c80`
  - `pc=0x406b60`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

这条 trace 把“请求体解析 -> submit_flag 分发 -> 页面回调 -> NULL 解引用”串成了同一条进程内路径，没有看到命令执行或子进程链参与。

## 关键数据流

### 1. 请求体解析与 `submit_flag` 抽取

- `fcn.00406c28` 先读取 POST body，然后在 `fcn.00406d14` 中原地切分 `key=value`，并把解析出的键值对地址写入栈上的数组。
- 解析结束后，`0x406eb8` 调用 `sym.cgi_setobject(sp+0x18, count)`。
- `sym.cgi_setobject` 在 `0x40b9ac` 显式读取 `submit_flag`:
  - `a0 = "submit_flag"`
  - `a1 = parsed_pairs`
  - `a2 = count`

这一步就是本样本里可解释的 source。

### 2. `submit_flag` 未命中任何已知 action

- `sym.cgi_setobject` 会把 `cgi_value("submit_flag", ...)` 的返回值放入 `s1`，随后在 `0x40ba44 .. 0x40bb90` 按固定表逐个比较。
- 当前 trace 的末段是:
  - `0x40ba44`
  - `0x40ba00`
  - `0x40ba08`
  - `0x40ba40`
  - `0x40ba00`
  - `0x40ba58`
  - `0x40bb34`
  - `0x40bb44`
  - `0x40bb5c`
  - `0x40bb70`
  - `0x40bb78`
  - `0x40bb90`
  - `0x40bbac`
- 如果命中已知分支，函数会跳到 `0x40bba0`，把一个固定字符串写入 `obj.refresh_time`。
- 但本样本 trace 直接从 `0x40bb90` 落到 `0x40bbac` 返回，说明没有命中任何已知 `submit_flag` 分支，也没有执行 `0x40bba0`。

因此，`body.submit_flag = "ﾌﾃ"` 造成的直接结果是: `cgi_setobject` 接受到了这个字段，但它不属于程序预期集合，导致后续状态没有被初始化。

### 3. `handle_request` 明确清空 refresh 状态

在进入后续回调之前，`sym.handle_request` 先做了以下写零操作:

- `0x409530`: 取 `obj.refresh_top`
- `0x409538`: `*obj.refresh_top = 0`
- `0x40953c`: 取 `obj.refresh_url`
- `0x409540`: `*obj.refresh_url = 0`
- `0x409544`: 取 `obj.refresh_time`
- `0x409548`: `*obj.refresh_time = 0`

这三个槽位本来位于 RW 段尾部/BSS 区域，默认就是零；这里又被当前请求路径再次明确清零。

## Sink 与崩溃点

`fcn.00406b60` 的函数开头就是:

- `0x406b78`: 取 `obj.refresh_url` 指针槽
- `0x406b80`: 取 `obj.refresh_time` 指针槽
- `0x406b90`: `lw v0, (v0)`，即解引用 `*obj.refresh_url`
- `0x406b94`: `lw v1, (v1)`，即解引用 `*obj.refresh_time`

由于前面:

- `handle_request` 把 `*obj.refresh_url` 清成了 `0`
- 当前 trace 又没有经过会回填 `refresh_url` 的路径

所以在 `0x406b90` 第一次二次解引用时就会访问 `NULL`。trace 只记录到 `pc=0x406b60` 随后立刻出现 `si_addr=NULL`，与这个首个危险解引用完全一致。

## 谁负责回填 `refresh_url`

- `sym.cgi_func` 中可以看到明确的 `refresh_url` 写入点:
  - `0x40bec8`: 取 `obj.refresh_url`
  - `0x40bed4`: 把 `"AUTO_upgrade_process.htm"` 写入 `*obj.refresh_url`
- 但本样本 trace 没有进入 `sym.cgi_func`，而是进入了 `fcn.00406c28 -> sym.cgi_setobject -> fcn.00406b60`

因此本次请求路径的核心缺陷不是“写坏了 refresh_url”，而是:

- 当前路径先清零 `refresh_url`
- 再用异常 `submit_flag` 走完解析/分发表
- 但没有补上 `refresh_url`
- 最后无条件把它当成有效字符串使用

## 为什么这是确认漏洞

这不是环境噪声，也不是单纯“崩了但解释不出来”:

- source 可解释: `body.submit_flag` 在 `0x40b9ac` 被显式读取
- 中间变量可解释: 它进入 `cgi_setobject` 的比较分支，决定是否执行 `0x40bba0` 等初始化路径
- 状态变化可解释: `handle_request` 已先把 `refresh_*` 置零，而当前 `submit_flag` 又让初始化分支全部落空
- sink 可解释: `0x406b90` 对 `NULL` 的二次解引用
- trace 闭环完整: `0x406c28 -> 0x406eb0 -> 0x40b95c -> 0x40bbac -> 0x409c74 -> 0x406b60 -> SIGSEGV(NULL)`

所以本样本应归类为真实的参数校验缺失导致的空指针解引用，而不是误报或证据不足。
