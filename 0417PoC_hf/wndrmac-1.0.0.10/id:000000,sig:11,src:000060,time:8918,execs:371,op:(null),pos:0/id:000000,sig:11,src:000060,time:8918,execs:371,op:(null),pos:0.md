# 漏洞分析: wndrmac-1.0.0.10 / id:000000,sig:11,src:000060,time:8918,execs:371,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd` `0x409640` `0x409680 (sprintf)`
- Source位置: `/usr/sbin/uhttpd` `0x40d544` `0x40d84c ($a0=$18 -> 0x409640)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 栈缓冲区溢出 / 返回地址覆盖
- 一句话根因: `.js` MIME 处理函数 `0x409640` 使用 `sprintf(sp+0x18, "/www/%s", user_input)` 把攻击者可控的 `handler_name` 无边界写入栈缓冲区，覆盖了 `saved $ra`，函数返回时跳到 `0x61616160` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` (`cc.jsaaaaaaaa...`) -> `0x40d84c` 处 `$a0=$18` -> `0x409680` 的 `sprintf` 第 3 个参数
  - `request.handler_name` 中的 `.js` -> `0x40d554` 的 `strstr($18, mime_handlers[i].ext)` 命中 `.js` 项 -> 选择 `mime_handlers[9].handler = 0x409640`
- 执行顺序:
  1. `container.console.log` 与 `trace/entry_trace.txt` 都显示本次样本最终触发 `SIGSEGV`，崩溃地址为 `si_addr=0x61616160`。
  2. `uhttpd` 在 `0x40d544` 开始遍历 `mime_handlers`；当 `request.handler_name` 包含 `.js` 时，`0x40d840/0x40d84c` 调用 `.js` 对应处理函数 `0x409640`。
  3. `0x409680` 的 `sprintf("/www/%s", $a0)` 将超长 `handler_name` 写入位于栈上的 `sp+0x18` 缓冲区，覆盖 `sp+0x12c` 的返回地址；随后 `0x409800` 恢复寄存器并在 `jr $ra` 时跳向 `0x61616160` 崩溃。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndrmac-1.0.0.10/wndrmac_1.0.0.10/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x409640`
- 命中的入口trace: `... -> 0x40d840 -> 0x40d84c -> 0x409640 -> 0x409688 -> 0x4096a0 -> 0x409800 -> SIGSEGV`
- 子进程trace链: 无。`entry_trace` 已直接落在 `uhttpd` 崩溃路径上，未见需要切换到其他进程补证。
- 关键pc地址:
  - `0x40d544`: 遍历 `mime_handlers`
  - `0x40d554`: 用 `strstr` 判断扩展名
  - `0x40d840`: 读取表项中的处理函数指针
  - `0x40d84c`: 以 `$a0=$18` 调用 `0x409640`
  - `0x409680`: `sprintf(sp+0x18, "/www/%s", $a0)`
  - `0x409698`: `fopen(sp+0x18, "r")`
  - `0x409800`: 函数尾声，从栈恢复 `ra`
  - `SIGSEGV si_addr=0x61616160`: 被污染的返回地址

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 提供了进入 sink 的实际字节串，且其中的 `.js` 同时充当分支选择器。
  - `request.prefix`、`body.time_zone`、`body.ntpadjust` 在当前崩溃链中没有证据显示流入 sink。
- 哪个函数读取了source字段:
  - 从当前允许输入能精确落地到的最早调用点是 `/usr/sbin/uhttpd` 的 MIME 分发表函数：`0x40d84c` 将 `$18` 作为第 1 个实参传给 `0x409640`。结合数据包内容和后续 `.js` 匹配，可将 `$18` 对应为 `request.handler_name`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `0x409640` 在 `0x409680` 调用 `sprintf`，目标缓冲区是当前栈帧中的 `sp+0x18`，格式串位于 `0x44c13c`，内容为 `"/www/%s"`。
  - 同一栈帧中 `saved $ra` 位于 `sp+0x12c`，两者相距 `0x114` 字节；因此超长 `%s` 内容会直接覆盖返回地址。
- 最终如何到达sink:
  - `request.handler_name = "cc.jsaaaaaaaa..."` -> `0x40d554` 用 `strstr` 命中 `.js` 表项 -> `0x40d84c` 调用 `.js` 处理函数 `0x409640($a0=request.handler_name, $a1=FILE*)` -> `0x409680` 将该字符串格式化进栈缓冲区 -> 覆盖 `saved $ra` -> `0x409800` 返回时崩溃。

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这不是“机械地把崩溃点当根因”。真实危险点是 `0x409680` 的 `sprintf`，而不是 `0x409800` 的 `jr $ra`。
  - 崩溃地址 `0x61616160` 明显来自攻击串中的连续 `a` 字节；其出现位置又恰好是函数返回地址读取点，和栈溢出模型完全一致。
  - `.js` 分发表、调用点、格式串和崩溃寄存器恢复路径可以闭合成完整的 `source -> variable -> sink` 链。
- 当前缺失的证据:
  - 没有从更早的 HTTP 解析函数名处继续向前恢复“JSON 字段被放进哪个结构体成员”的精确成员名；但 `0x40d84c` 之后的数据流、控制流与崩溃结果已经足以确认漏洞。
- 对当前现象的替代解释:
  - 更合理的替代解释不是空指针或随机崩溃，而是 `sprintf` 触发的返回地址覆盖。`fopen` 失败只解释了为什么函数很快走到尾声，不解释 `0x61616160` 这种用户态花样地址。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` 末尾: `0x40d840 -> 0x40d84c -> 0x409640 -> 0x409688 -> 0x4096a0 -> 0x409800 -> --- SIGSEGV {si_addr=0x61616160} ---`
  - `trace/usr_sbin_uhttpd.txt` 也显示请求处理最终进入 `uhttpd` 主进程，无需依赖子进程解释。
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x40d544` 载入 `mime_handlers`；表项 `mime_handlers[9] = { ".js", "text/javascript", ..., 0x409640, ... }`
  - `0x40d554` 调用 `strstr($18, ".js")`，命中后在 `0x40d840/0x40d84c` 间接调用 `0x409640`
  - `0x409680`: `jalr sprintf`，参数为 `dest=sp+0x18`, `fmt="/www/%s"`, `src=$a0`
  - `0x409800`: 从 `sp+0x12c` 取回 `ra` 后 `jr $ra`；崩溃地址 `0x61616160` 说明该槽位已被输入覆盖
