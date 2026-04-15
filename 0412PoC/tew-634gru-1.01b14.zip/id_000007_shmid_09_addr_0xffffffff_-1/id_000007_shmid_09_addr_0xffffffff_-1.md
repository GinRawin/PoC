# 漏洞分析: tew-634gru-1.01b14.zip / id:000007,shmid:09,addr:0xffffffff,-1

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x40a654 0x40ec74`
- Source位置: `/sbin/httpd 0x40a654 0x40ec18`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `do_apply_post` 从 `body.date` 读取用户输入后，直接把它作为 `%s` 参数传入 `_system("date -s %s ", date)`，最终经 `/bin/sh -c` 执行，没有 shell 级过滤。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/" + request.handler_name="system_time.cgi*?version.txt"` -> 选择系统时间设置路径
  - `body.date="1"` -> `get_cgi("date")` 返回值 `s0` -> `_system("date -s %s ", s0)` 的格式化参数 -> shell 命令 `date -s 1 `
  - 其余大量 body 字段 (`Secondary`、`IsAccessPoint`、`SSID` 等) -> 当前已确认路径中未见进入该命令模板
- 执行顺序:
  1. `POST /system_time.cgi*?version.txt` 命中系统时间处理逻辑。
  2. `do_apply_post` 在 `0x40ec18` 调用 `get_cgi("date")`，取出 `body.date`。
  3. `do_apply_post` 在 `0x40ec74` 调用 `_system("date -s %s ", date)`。
  4. `httpd` fork 后 `execve("/bin/sh", {"sh","-c","date -s 1 "})`，shell 再派生 `execve("/bin/date", {"date","-s","1"})`。
  5. `date` 因参数非法返回错误，但危险命令执行已发生。

## 原始请求

- 方法: `POST`
- URL: `/system_time.cgi*?version.txt`
- handler: `system_time.cgi*?version.txt`
- URL 来源: `VulPacket.json.request`
- body 中与漏洞链条相关的关键字段:
  - `date=1`
- 其他 body 字段数量很多，但当前证据只支持 `date` 进入命令执行链

## Trace映射

- 入口二进制: `/sbin/httpd`
- `main` 地址: `0x40582c`
- 命中的入口 trace: `trace/sbin_httpd.txt`
- 子进程链:
  - `httpd(pid 14)` -> `sh(pid 17)` -> `date(pid 20)`
- 关键 trace:
  - `trace/sbin_httpd.txt:341-344`
    - `pc=0x436b00`
    - `14 fork() = 17`
    - `14 fork() = 0`
    - `17 execve("/bin/sh",{"sh","-c","date -s 1 ",NULL}) = 0`
  - `trace/17_tb_log.txt:673`
    - `20 execve("/bin/date",{"date","-s","1",NULL}) = 0`
  - `trace/17_tb_log.txt:761`
    - `17 exit(1)`
  - `trace/20_tb_log.txt:149`
    - `20 exit(1)`

## 关键数据流

`do_apply_post` 中的关键片段位于 `0x40ec0c-0x40ec74`:

- `0x40ec0c-0x40ec18`
  - 调用 `get_cgi(<date字符串>)`
  - 返回值保存到 `s0`
- `0x40ec50-0x40ec74`
  - `a1 = s0`
  - `a0 = "date -s %s "`
  - 调用 `_system()`

因此可以写出闭环:

- `body.date`
  -> `get_cgi("date")`
  -> `s0`
  -> `_system("date -s %s ", s0)`
  -> `/bin/sh -c "date -s 1 "`
  -> `/bin/date -s 1`

## Console与反编译证据

- `container.console.log`
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /bin/date`
  - `date: invalid date '1'`
- 二进制字符串
  - `system_time.cgi*`
  - `version.txt`
  - `date -s %s `
- 关键反汇编
  - `0x40ec10 lw t9, -31564(gp)`，`0x40ec18 jalr t9` -> 读取 `date`
  - `0x40ec58 lw t9, -32604(gp)` -> `_system`
  - `0x40ec5c addiu a0, ..., "date -s %s "`
  - `0x40ec74 jalr t9`

## 为什么这是确认漏洞

- 已有可解释 source:
  - `get_cgi("date")` at `0x40ec18`
- 已有可解释 sink:
  - `_system("date -s %s ", date)` at `0x40ec74`
- 已有完整闭环:
  - `body.date -> s0 -> _system format arg -> /bin/sh -c`
- trace / console / 反汇编一致:
  - trace 给出 `/bin/sh -c "date -s 1 "`
  - trace 继续到 `/bin/date -s 1`
  - console 给出 `date: invalid date '1'`

后面的参数错误只是当前 payload 的执行结果，不影响命令注入成立；真正的危险点是用户输入未经 shell 过滤就进入了 `sh -c`。
