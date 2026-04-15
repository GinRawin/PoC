# 漏洞分析: tew-652brp-1.10.29.zip / id:000004,shmid:000005,cmdinj,src:000091,time:99991,execs:2327,op:(null),pos:0,ipc:3

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x419b60 0x419f94`
- Source位置: `/sbin/httpd 0x419b60 0x419cdc`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `/system_time.cgi*` 处理路径把 `body.date` 直接格式化进 `date -s %s `，随后通过 `_system` 交给 `/bin/sh -c` 执行，没有做任何安全过滤。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=system_time.cgi*` -> 进入 `/system_time.cgi*`
  - `body.date` -> `set_basic_api` 中 `get_cgi(<field="date">)` 返回值 `s2` -> `sprintf(s2_buf, "date -s %s ", s2)` -> `_system("date -s ...")`
  - `body.countdown_time` -> 同一 handler 的其他配置字段，不是命令模板来源
  - `body.html_response_page` / `body.html_response_return_page` 只是请求体参数，不是原始 URL
- 执行顺序:
  1. `POST /system_time.cgi*` 进入 `httpd_main`，然后转入 `do_apply_post` / `set_basic_api` 这条配置处理链。
  2. `set_basic_api` 在 `0x419cdc` 通过 `get_cgi` 取出名为 `date` 的字段值。
  3. `set_basic_api` 在 `0x419f78` 用格式串 `date -s %s ` 生成命令。
  4. `set_basic_api` 在 `0x419f94` 调 `_system`。
  5. trace 显示子进程先 `execve("/bin/sh","-c","date -s 222...wzq...",NULL)`，再 `execve("/bin/date",{"date","-s","222...wzq...",NULL})`，最终 `date` 报 `invalid date`。

## 原始请求

- 方法: `POST`
- URL/handler: `/system_time.cgi*`
- 来源字段: `packet_1.request.method`, `packet_1.request.prefix`, `packet_1.request.handler_name`
- `body.date`、`body.countdown_time`、`body.reboot_type`、`body.html_response_page` 等都只是请求体参数

## Trace映射

- 入口二进制: `/sbin/httpd`
- `main` 地址: `0x40572c`
- 命中的入口 trace: `trace/sbin_httpd.txt`
- 关键 trace:
  - `trace/sbin_httpd.txt:238` `pc=0x40a4bc` 命中 `do_apply_post`
  - `trace/sbin_httpd.txt:341-343` `fork()` 后 `execve("/bin/sh",{"sh","-c","date -s 222...wzq... ",NULL})`
  - `trace/17_tb_log.txt:673` `execve("/bin/date",{"date","-s","222...wzq...",NULL})`
  - `trace/17_tb_log.txt:761` `17 exit(1)`
- 子进程链: `httpd(pid 14) -> /bin/sh(pid 17) -> /bin/date(pid 20)`

## 数据流细节

- `0x419cdc`: `get_cgi(<field-name>)`，该轮遍历命中字段 `date`
- `0x419f60-0x419f78`: `sprintf(..., "date -s %s ", ...)`
- `0x419f8c-0x419f94`: `_system("date -s ...")`

控制台与 trace 一致:

```text
[qemu] doing qemu_execven on filename /bin/sh
[qemu] doing qemu_execven on filename /bin/date
date: invalid date `222222...wzq...'
```

这说明用户可控的 `date` 字段已经未经约束地进入 shell 命令模板并被执行。当前样本没有使用分号等元字符，因此只表现为 `date` 参数非法；但命令注入本身已经成立。

## 误报检查

- 不是误报:
  - source 可解释: `get_cgi` 读取 `date`
  - sink 可解释: `_system`
  - 数据流可解释: `body.date -> sprintf("date -s %s ") -> /bin/sh -c -> /bin/date`
  - trace / console / 反汇编三者一致
- 缺失的不是关键闭环，而只是“利用载荷中的进一步 shell 元字符”。即使当前样本只是无效日期字符串，危险执行路径也已真实发生。

## 证据

- 关键反汇编:
  - `0x419cdc` `get_cgi`
  - `0x419f78` `sprintf`
  - `0x419f94` `_system`
  - 字符串: `system_time.cgi*`, `date -s %s `
- 关键 trace:
  - `trace/sbin_httpd.txt:343` `/bin/sh -c "date -s 222...wzq... "`
  - `trace/17_tb_log.txt:673` `/bin/date -s 222...wzq...`
- 关键控制台:
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /bin/date`
  - `date: invalid date '222...wzq...'`

## 命中benchmark:否

## 0-day:是