## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / DoS
- Source位置: `0x438d04`-`0x438d1c`，`jalr sym.cgi_value` 读取参数名 `wl_ssid`
- Sink位置: `0x438d54`-`0x438d60`，`jalr sym.imp.nvram_set`，实参为 `a0="wl_ssid"`，`a1=NULL`
- 一句话根因: `submit_flag=wlan_brs` 选中无线快速配置处理函数 `0x438cdc` 后，代码未检查 `cgi_value("wl_ssid", ...)` 的返回值，直接把 `NULL` 作为第二实参传给 `nvram_set("wl_ssid", NULL)`，导致崩溃。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag="wlan_brs"` -> `cgi_setobject` 在 `0x40b9a8` 读取该字段，并命中分发表项 `0x471a94 {0x44e218("wlan_brs"), 0x0000000d, 0x438cdc}`
  - `body.wl_ssid` 缺失 -> `0x438d18` 调用 `cgi_value("wl_ssid", param_table, param_count)` 返回 `v0=NULL`
  - `v0` 在 `0x438d4c` 的 delay slot 被保存到 `s0`
  - `0x438d54`/`0x438d5c` 调用 `nvram_set` 时，delay slot `0x438d60` 将 `a1=s0=NULL`
- 执行顺序:
  1. `uhttpd` 处理 `POST /apply.cgi`
  2. `0x40b9a8` 读取 `submit_flag`
  3. `0x471a94` 的 `wlan_brs` 表项把执行流送入 `0x438cdc`
  4. `0x438d18` 读取缺失的 `wl_ssid`，得到 `NULL`
  5. `0x438d30`-`0x438d48` 生成键名 `"wl_ssid"`
  6. `0x438d5c` 调用 `nvram_set("wl_ssid", NULL)`，随后 trace 在 `0x438d50` 后终止并出现 `SIGSEGV`

## 请求与入口

- 原始请求: `POST /apply.cgi`
- handler 以 `VulPacket.json` 的 `request` 为准，`body.show_traffic=WANIPConnection` 只是 body 参数，不是 URL。
- `trace_summary.json` 已将入口二进制精确匹配到 `/usr/sbin/uhttpd`，`main=0x4047d4`。
- 当前目录缺少 `analysis_report_template.md`，本报告按任务要求保留 `## 摘要` 为首个核心部分，并补全 source/sink/dataflow 章节。

## 关键证据

- `trace/usr_sbin_uhttpd.txt:690`-`710`：先后进入 `cgi_setobject(0x40b95c)`、`cgi_value(0x40b4a4)`、`fcn.0040adcc(0x40adcc)`，随后转入 `0x438cdc`
- `trace/usr_sbin_uhttpd.txt:711`：`pc=0x438cdc`
- `trace/usr_sbin_uhttpd.txt:712`：从 `cgi_value("wl_ssid", ...)` 返回后落在 `pc=0x40b514`
- `trace/usr_sbin_uhttpd.txt:713`：`pc=0x438d20`
- `trace/usr_sbin_uhttpd.txt:714`：`pc=0x438d50`
- `trace/usr_sbin_uhttpd.txt:715`：`SIGSEGV {si_addr=NULL}`
- `container.console.log`：`[GreenHouseQEMU] SIGSEGV CAUGHT!`

## Source核验

`0x438cdc` 是 `wlan_brs` 对应的真实处理函数。其入口调用序列如下：

```asm
0x438d04  lw   t9, -sym.cgi_value(gp)
0x438d08  lui  a0, 0x46
0x438d10  addiu a0, a0, -0x770c   ; "wl_ssid"
0x438d14  move a1, s2             ; CGI 参数表指针
0x438d18  jalr t9                 ; cgi_value("wl_ssid", s2, s3)
0x438d1c  move a2, s3             ; CGI 参数个数
```

- `0x4588f4` 对应字符串 `"wl_ssid"`。
- `VulPacket.json` 中不存在 `body.wl_ssid`，因此这里最合理的返回值就是 `NULL`。
- trace 在 `0x438cdc` 后立即出现一次 `0x40b514`，与 `cgi_value` 返回地址完全一致，说明 source 的确发生在这里。

## 分发表与处理函数核验

`cgi_setobject` 先读取 `submit_flag`，再从 `cgi_action` 分发表取对应处理函数：

```asm
0x40b9a8  addiu a0, a0, -0x22cc   ; "submit_flag"
0x40b9ac  jal   sym.cgi_value
...
0x40ba20  lw    t9, 8(s0)         ; 取表项中的处理函数指针
0x40ba30  jalr  t9
0x40ba34  sw    v1, (v0)
```

分发表 `0x471a94` 的真实内容为：

```text
0x471a94: 0x44e218 0x0000000d 0x438cdc
```

- `0x44e218` 是字符串 `"wlan_brs"`
- 第三个字是函数指针 `0x438cdc`

这证明本次 crash 不是泛化到其他无线函数，而是 `submit_flag=wlan_brs` 直接选中了 `0x438cdc`。

## Sink核验

`0x438d20` 之后的指令把 NVRAM 键名和待写入值装入寄存器，并在 `0x438d5c` 调用 `nvram_set`：

```asm
0x438d30  addiu s1, sp, 0x18
0x438d34  addiu a2, a2, -0x1d40   ; "wl_"
0x438d3c  addiu a3, a3, 0x7954    ; "ssid"
0x438d48  jalr  t9                 ; sprintf(s1, "%s%s", "wl_", "ssid")
0x438d4c  move  s0, v0             ; delay slot，保存 cgi_value 返回值到 s0

0x438d54  move  a0, s1             ; a0 = "wl_ssid"
0x438d58  lw    t9, -sym.imp.nvram_set(gp)
0x438d5c  jalr  t9
0x438d60  move  a1, s0             ; delay slot，a1 = NULL
```

- `0x45e2c0` 是字符串 `"wl_"`
- `0x457954` 是字符串 `"ssid"`
- 因此 `s1` 缓冲区在调用前被构造成 `"wl_ssid"`
- `s0` 来自前一条 `cgi_value("wl_ssid", ...)` 的返回值；当字段缺失时，这里就是 `NULL`

trace 在 `pc=0x438d50` 后直接崩溃，没有再出现新的用户态 PC，符合“进入未跟踪的导入函数 `nvram_set` 后立即因 `a1=NULL` 崩溃”的模式。

## Source -> Variable -> Sink 数据流

完整链条如下：

1. 请求 `POST /apply.cgi` 的 body 中包含 `submit_flag=wlan_brs`
2. `0x40b9a8` 读取 `submit_flag`，命中 `0x471a94` 的 `wlan_brs -> 0x438cdc`
3. `0x438d04`-`0x438d1c` 读取字段 `wl_ssid`
4. 因为 `VulPacket.json` 中 `wl_ssid` 缺失，`cgi_value` 返回 `NULL`
5. `0x438d4c` 将该返回值保存到局部寄存器 `s0`
6. `0x438d30`-`0x438d48` 构造 NVRAM 键名 `"wl_ssid"` 到栈缓冲区 `s1`
7. `0x438d5c` 调用 `nvram_set(a0=s1, a1=s0)`，即 `nvram_set("wl_ssid", NULL)`
8. 导致空指针解引用并触发 `SIGSEGV`

## 为什么不是误报

- 崩溃路径与 trace 完全一致，且 source/sink 都回到了真实 callsite。
- `submit_flag` 的值不是由日志或字符串猜测，而是由 `cgi_setobject` 的 `cgi_value("submit_flag", ...)` 和分发表 `0x471a94` 双重验证。
- sink 不是泛化的“0x438d50 附近崩溃”，而是明确到 `0x438d5c` 的 `nvram_set` 调用，以及 delay slot `0x438d60` 把 `NULL` 装入 `a1`。
- 当前包里虽然还有很多超长字段，但本次崩溃在读取这些字段之前就已经因为缺失的 `wl_ssid` 触发，因而真正的根因不是长字符串溢出。

## 结论

本 case 应更新为 `确认漏洞`。真实漏洞是 `/usr/sbin/uhttpd` 在处理 `submit_flag=wlan_brs` 时，对必需字段 `wl_ssid` 缺少非空检查，最终将 `NULL` 直接传入 `nvram_set("wl_ssid", NULL)` 并导致进程崩溃。
