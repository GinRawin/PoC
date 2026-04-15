# 漏洞分析: us-ac500v1br-v1.0.0.14-en-td.zip / id:000000,shmid:11,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/bin/httpd fcn.000279d4 0x00027b7c`
- Source位置: `/bin/httpd fcn.000282a8 0x000282d8`
- 漏洞二进制: `/bin/httpd`
- 漏洞类型: `参数校验缺失`
- 一句话根因: `httpd` 接受了畸形请求路径 `/index.asp?/cgi-bin`，导致请求对象中的重定向缓冲区未初始化；`formQuickIndex` 提交完成后进入统一跳转路径，`fcn.000279d4` 在未判空的情况下对该字段执行 `strlen`，最终触发空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/" + request.handler_name="/index.asp?/cgi-bin"` -> 请求行 URI token -> `fcn.000282a8` 解析后的 request state -> `ctx+0xa4` 重定向字符串保持为 `NULL`
  - `body.wans="1"` -> `formQuickIndex` 提交后的回跳参数名 `"wans"` -> `sym.formQuickIndex` 在 `0x0003ea78` 调用 `fcn.000294d8(ctx, "wans")`
  - `body.test` -> 当前 trace/反汇编中未观察到参与崩溃路径
- 执行顺序:
  1. `httpd` 接收 `POST /index.asp?/cgi-bin HTTP/1.1`，在 `fcn.000282a8` 中用 `strtok` 拆分请求行并接受了畸形 URI。
  2. 请求进入 `sym.formQuickIndex`，期间派生多个 `/bin/sh` 子进程执行 `killall -9 dhcps`、`rm -rf /etc/cert`、`route add default gw`、`cfm Post netctrl 58`。
  3. `sym.formQuickIndex` 在 `CommitCfm` 成功后调用 `fcn.000294d8(..., "wans")` 生成跳转页面。
  4. 跳转辅助路径进入 `fcn.0001cc70 -> fcn.000279d4`，`fcn.000279d4` 在 `0x00027b7c` 对 `ctx+0xa4` 调用 `strlen`。
  5. 由于该字段仍为 `NULL`，入口进程 `20_tb_log.txt` 在结尾触发 `SIGSEGV`，console 也记录了 `Segmentation fault (core dumped)`。

## 原始请求

- 方法: `POST`
- URL来源: `VulPacket.json.packet_1.request`
- 路径还原: `/index.asp?/cgi-bin`
- handler 解释: 原始请求路径来自 `request.handler_name`，不是 `body` 中的任意字段
- body 参数:
  - `test=22222222222222222222222222222222`
  - `wans=1`

## Trace映射

- 入口二进制: `/bin/httpd`
- 入口 trace: `trace/20_tb_log.txt`
  - 该文件从 ELF 入口 `pc=0xd5f0` 开始，且在末尾出现 `SIGSEGV`
- 子进程链:
  - `20 -> 22 execve("/bin/sh","sh","-c","killall -9 dhcps")`
  - `20 -> 28 execve("/bin/sh","sh","-c","rm -rf /etc/cert")`
  - `20 -> 34 execve("/bin/sh","sh","-c","echo " nameserver 8.8.8.8" > /etc/resolv.conf")`
  - `20 -> 37 execve("/bin/sh","sh","-c","route add default gw ")`
  - `20 -> 43 execve("/bin/sh","sh","-c","echo '' > /tmp/userListFile")`
  - `20 -> 46 execve("/bin/sh","sh","-c","cfm Post netctrl 58")`
- 关键 trace 证据:
  - `trace/20_tb_log.txt:161` `46 execve("/bin/sh",{"sh","-c","cfm Post netctrl 58",NULL}) = 0`
  - `trace/20_tb_log.txt:1392` `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键数据流

- `fcn.000282a8` 从请求行中拆出 URI token；该路径对 `/index.asp?/cgi-bin` 这种畸形 `index.asp?` + `cgi-bin` 组合未做拒绝。
- `sym.formQuickIndex` 在 `0x0003ea30` 调用 `CommitCfm`，随后在 `0x0003ea78` 调用 `fcn.000294d8(ctx, "wans")` 构造跳转目标。
- `fcn.000294d8` 会基于 `HTTP_HOST` 和传入的参数名拼接 `http://%s/%s` 形式的目标，再继续进入 HTML/redirect 包装逻辑。
- 包装逻辑进入 `fcn.0001cc70`，最终在 `0x0001cd58` 调用 `fcn.000279d4`。
- `fcn.000279d4` 的崩溃分支会先取 `ctx+0xa4`，随后在 `0x00027b7c` 执行 `strlen(ctx->a4)`；当前请求状态下该字段仍为 `NULL`，于是触发空指针解引用。

## 关键反汇编证据

- `sym.formQuickIndex`
  - `0x0003ea30` `bl sym.imp.CommitCfm`
  - `0x0003ea70` 附近引用字符串 `"wans"`
  - `0x0003ea78` `bl fcn.000294d8`
- `fcn.0001cc70`
  - `0x0001cd58` `bl fcn.000279d4`
- `fcn.000279d4`
  - `0x00027b74` `mov r0, r3`
  - `0x00027b7c` `bl sym.imp.strlen`
  - 该分支前仅检查 `ctx+0xa4` 是否为非空字符串的某些状态位，没有保证指针本身已经初始化

## Console与判定理由

- `container.console.log` 末尾出现:
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`
  - `Segmentation fault (core dumped)`
- 这不是单纯环境噪声:
  - 崩溃发生在 `httpd` 主进程自身，而不是某个外部工具进程
  - trace 给出了稳定的 `CommitCfm -> redirect helper -> fcn.000279d4 -> SIGSEGV` 闭环
  - 静态分析可以解释 `si_addr=NULL`，并与 `0x00027b7c` 的 `strlen(NULL)` 型崩溃一致

## 误报检查

- 不是误报的原因:
  - 可解释的 source: 畸形请求 URL 在 `fcn.000282a8` 被接受
  - 可解释的 sink: `fcn.000279d4` 在 `0x00027b7c` 对空指针执行 `strlen`
  - 可解释的数据流: `request URL -> request state(ctx+0xa4 未初始化) -> CommitCfm 后 redirect helper -> strlen(NULL)`
  - 与 trace/console/反汇编三者一致
- 剩余不确定点:
  - `ctx+0xa4` 的语义名称在 stripped 二进制中无法直接恢复，只能确认其为跳转/拼接用字符串字段
  - `body.wans` 更像触发 `formQuickIndex` 提交后回跳逻辑的上下文参数，而不是直接写入崩溃指针本身
