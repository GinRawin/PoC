# 漏洞分析: tew-632brp-1.010b32.zip / id:000000,shmid:000005,cmdinj,src:000014,time:12125,execs:194,op:(null),pos:0,ipc:3

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd` `0x40a4bc` `0x40eadc`
- Source位置: `/sbin/httpd` `0x40a4bc` `0x40ea80`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `system_time.cgi*` 分支直接把 `body.date` 作为 `%s` 代入 `date -s %s`，随后调用 `_system`，导致用户输入在 `/bin/sh -c` 中未转义执行。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` + `request.prefix=/` + `request.handler_name=system_time.cgi*` -> 原始请求 URL `/system_time.cgi*` -> 进入 `/sbin/httpd` 的 `do_apply_post` 对应分支
  - `body.date` -> `get_cgi("date")` 返回值 `s0` -> `a1` at `0x40eab8` -> `_system("date -s %s", s0)` at `0x40eadc`
  - `body.test` -> 未在已命中的分支、trace 或 console 中观察到被使用
- 执行顺序:
  1. `/system_time.cgi*` 收到 POST 请求，`/sbin/httpd` 在入口 trace `sbin_httpd.txt` 中处理该 CGI。
  2. `do_apply_post` 在 `0x40ea80` 调用 `get_cgi("date")` 读取 `body.date`。
  3. 同一分支把返回值保存到 `s0`，并在 `0x40eab8` 作为 `_system` 的第二个参数准备命令字符串。
  4. `0x40eadc` 调用 `_system`，模板常量为 `date -s %s`，QEMU trace 记录到子进程 `execve("/bin/sh", {"sh","-c","date -s 222222222wzq22222222222222222222 ",NULL})`。
  5. shell 再派生 `/bin/date -s 222222222wzq22222222222222222222`，控制台输出 `invalid date`，说明本样本触发的是命令执行路径而非崩溃。

## 原始请求

- `VulPacket.json` 显示请求方法是 `POST`。
- 请求路径来源于 `request.prefix=/` 与 `request.handler_name=system_time.cgi*`，因此原始请求 URL 应按 `/system_time.cgi*` 理解。
- 请求体里真正相关的参数是 `body.date=222222222wzq22222222222222222222`。
- `body.test` 只是请求体中的另一个参数，不是 URL，也没有在当前漏洞链中出现。

## Trace映射

- 父目录 `binary_summary.json` 给出的入口二进制是 `/sbin/httpd`，`main` 地址为 `0x40572c`。
- 当前 case 的 `trace_summary.json` 已把 `14_tb_log.txt` 重命名为 `trace/sbin_httpd.txt`，并标记为 `exact_main` 命中。
- `trace/sbin_httpd.txt` 先命中 `pc=0x40572c`，随后在第 342-344 行出现：
  - `14 fork() = 17`
  - `17 execve("/bin/sh",{"sh","-c","date -s 222222222wzq22222222222222222222 ",NULL}) = 0`
- 子进程 trace `trace/17_tb_log.txt` 继续显示：
  - 第 574-575 行：`17 fork() = 20` / `17 fork() = 0`
  - 第 673 行：`20 execve("/bin/date",{"date","-s","222222222wzq22222222222222222222",NULL}) = 0`
  - 第 761 行：`17 exit(1)`
- `trace/20_tb_log.txt` 第 154 行是 `20 exit(1)`，与 `/bin/date` 失败一致。

## 关键地址与数据流

- 在 `/sbin/httpd` 的 `do_apply_post` 内部，`0x40ea80` 通过 `get_cgi("date")` 取出 CGI 参数，字符串字面量 `date` 位于 `0x43960c`。
- 取回的 `body.date` 指针保存到寄存器 `s0`，随后在 `0x40eab8` 被移动到 `_system` 的第二个参数寄存器 `a1`。
- `0x40eac4` 装载命令模板 `date -s %s`（常量位于 `0x4379dc`），`0x40eadc` 真正调用 `_system`。
- `_system` 的行为被 trace 直接观测到：父进程派生 `/bin/sh -c "date -s <body.date> "`，说明 `body.date` 已经未经任何引号包装或转义进入 shell 命令。

## Console与行为证据

- `container.console.log` 记录：
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /bin/date`
  - `date: invalid date \`222222222wzq22222222222222222222'`
- 这与 trace 中的 `/bin/sh` -> `/bin/date` 两级进程链完全一致。
- 当前 payload 没有包含分号、反引号或 `$()` 等额外 shell 元字符，因此样本只表现为“用户可控命令参数被 shell 执行后失败”，没有继续扩展成额外命令执行；但 sink 已经是 `_system`，因此漏洞类型仍然是命令注入。

## 判定理由

- source 明确：`get_cgi("date")` 在 `0x40ea80` 读取了请求体字段 `body.date`。
- sink 明确：`_system("date -s %s", s0)` 在 `0x40eadc` 被调用。
- `source -> variable -> sink` 闭环明确：`body.date -> get_cgi("date") -> s0/a1 -> _system -> /bin/sh -c "date -s <body.date>"`。
- reverse/trace/console 三类证据一致，因此不是普通运行失败或环境噪声，而是可解释的真实命令拼接漏洞。
