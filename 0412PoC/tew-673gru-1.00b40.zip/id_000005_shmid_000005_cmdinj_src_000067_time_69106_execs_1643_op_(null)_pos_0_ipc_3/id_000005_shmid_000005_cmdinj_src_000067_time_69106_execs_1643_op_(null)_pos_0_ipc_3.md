# 漏洞分析: tew-673gru-1.00b40.zip / id:000005,shmid:000005,cmdinj,src:000067,time:69106,execs:1643,op:(null),pos:0,ipc:3

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/sbin/httpd 0x40fc8c 0x40fd2c`
- Source位置: `/sbin/httpd 0x40fc8c 0x40fcd0`
- 漏洞二进制: `/sbin/httpd`
- 漏洞类型: `命令注入`
- 一句话根因: `system_time.cgi*` 处理逻辑将 `body.date` 经 `get_cgi("date")` 直接作为 `_system("date -s %s ", user_date)` 的格式化参数传入 `/bin/sh -c`，没有任何过滤或转义，导致攻击者可控数据进入 shell 命令模板。
- 数据包字段 -> 变量赋值:
  - `request.prefix="/" + request.handler_name="system_time.cgi*"` -> `parse_http_url_request() @ 0x40fcb4` 选择 `system_time.cgi*` 对应处理函数
  - `body.date="2222222222222wzq2222222222222222"` -> `get_cgi("date") @ 0x40fcd0` -> 返回值 `v0` -> `s0 @ 0x40fcdc` -> `a1 @ 0x40fd08` -> `_system("date -s %s ", a1) @ 0x40fd2c`
  - `body.html_response_return_page` -> `get_cgi("html_response_return_page") @ 0x40fcfc` -> `v0/s0` -> `absolute_path(s0) @ 0x40fd44` -> 仅影响返回页面，不参与命令 sink
  - `body.test` / `body.lan_device_name` / `body.wps_pin` / `body.admin_password` / `body.customer_variable_00` -> 在当前命中的执行路径中未观察到进入危险 sink
- 执行顺序:
  1. `POST /system_time.cgi*` 命中系统时间设置 handler；原始 URL 来自 `request`，不是 body 中任何看起来像路径的值。
  2. 处理函数在 `0x40fcd0` 读取 `date` 参数，并把返回指针保存在 `s0`。
  3. 同一函数在 `0x40fd2c` 调用 `_system("date -s %s ", s0)`，将攻击者输入直接嵌入命令模板。
  4. `httpd` 随后 `fork()` 并 `execve("/bin/sh", {"sh","-c","date -s <body.date> "})`，子进程再 `execve("/bin/date", {"date","-s","<body.date>"})`。
  5. 当前样本没有形成崩溃，而是因为非法日期字符串导致 `/bin/date` 报错并 `exit(1)`；但 source -> sink -> shell 执行链条已经闭环，属于确认的命令注入。

## Trace映射

- 入口二进制: `/sbin/httpd`
- Main地址: `0x405d6c`
- 命中的入口trace: `trace/sbin_httpd.txt`
- 子进程trace链:
  - `trace/12_tb_log.txt`: `12 fork() = 14`，`14 execve("/sbin/httpd",{"/sbin/httpd",NULL}) = 0`
  - `trace/sbin_httpd.txt`: `14 fork() = 17`，`17 execve("/bin/sh",{"sh","-c","date -s 2222222222222wzq2222222222222222 ",NULL}) = 0`
  - `trace/17_tb_log.txt`: `17 fork() = 20`，`20 execve("/bin/date",{"date","-s","2222222222222wzq2222222222222222",NULL}) = 0`
  - `trace/20_tb_log.txt`: `20 exit(1)`
  - `trace/17_tb_log.txt`: `17 exit(1)`
- 关键pc地址:
  - `0x40fcd0`: `get_cgi("date")`
  - `0x40fcfc`: `get_cgi("html_response_return_page")`
  - `0x40fd2c`: `_system("date -s %s ", user_date)`
  - `0x40fd44`: `absolute_path(s0)`

## 数据流细节

- 原始请求方法、URL、handler:
  - 方法来自 `packet_1.request.method`: `POST`
  - 路径来自 `packet_1.request.prefix="/"` 与 `packet_1.request.handler_name="system_time.cgi*"`
  - `body.date` 只是请求体参数；它不是原始 URL，而是在 handler 内部被再次取出作为命令参数
- 哪些数据包字段控制了哪些变量:
  - `body.date` 控制 `get_cgi("date")` 的返回指针，并最终作为 `_system` 的第 2 个实参
  - `body.html_response_return_page` 只影响重定向页面路径
  - 其余超长字段在本次命中的 handler 路径里没有与 shell 命令模板对齐
- 哪个函数读取了 source 字段:
  - `0x40fc8c` 开始的处理函数先调用 `parse_http_url_request()`
  - 随后 `0x40fcc8` 装载 `get_cgi`
  - `0x40fcd4` 延迟槽形成字符串地址 `0x43c4d4 ("date")`
  - `0x40fcd0` 调用 `get_cgi("date")`
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 这里不是先显式 `sprintf` 到栈缓冲区，而是直接把固定模板 `0x43b6c0 ("date -s %s ")` 传给 `_system`
  - `0x40fd08` 将前面取到的用户值放入 `a1`
  - `0x40fd14` 将模板地址放入 `a0`
  - `0x40fd2c` 调用 `_system(a0, a1)`，实际运行时展开成 `date -s 2222222222222wzq2222222222222222 `
- 最终如何到达 sink:
  - `body.date` -> `get_cgi("date") @ 0x40fcd0` -> `s0` -> `a1 @ 0x40fd08` -> `_system("date -s %s ", a1) @ 0x40fd2c` -> `fork()` -> `execve("/bin/sh", {"sh","-c","date -s <user>"})` -> `execve("/bin/date", {"date","-s","<user>"})`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - source 明确：`body.date -> get_cgi("date")`
  - sink 明确：`_system("date -s %s ", user_date)`，并且 trace 已经看到 `execve("/bin/sh", {"sh","-c","date -s <user>"})`
  - 数据流明确：`source -> 变量(s0/a1) -> 命令模板(a0) -> /bin/sh -c`
  - console 与 trace 一致地表明用户输入原样进入 shell 命令
- 当前缺失的证据:
  - 没有必要再要求崩溃或二次 payload；对于命令注入，看到用户可控字符串进入 `/bin/sh -c` 已经足够
- 对当前现象的替代解释:
  - 当前样本表面现象只是 `date` 命令收到非法日期而失败，这只能解释 `exit(1)`，不能否定用户输入已经进入危险 shell sink
  - 更合理的解释是：该 handler 存在真实命令注入面，只是本次 fuzz 字符串没有使用 shell 元字符，所以触发了普通命令失败而不是更明显的命令链执行

## 证据

- 关键trace行:
  - `trace/sbin_httpd.txt:361`: `14 fork() = 17`
  - `trace/sbin_httpd.txt:363`: `17 execve("/bin/sh",{"sh","-c","date -s 2222222222222wzq2222222222222222 ",NULL}) = 0`
  - `trace/17_tb_log.txt:574`: `17 fork() = 20`
  - `trace/17_tb_log.txt:671`: `20 execve("/bin/date",{"date","-s","2222222222222wzq2222222222222222",NULL}) = 0`
  - `trace/20_tb_log.txt:154`: `20 exit(1)`
  - `trace/17_tb_log.txt:756`: `17 exit(1)`
- 关键容器日志行:
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /bin/date`
  - `date: invalid date '2222222222222wzq2222222222222222'`
- 关键反编译证据:
  - `0x43a108`: `"system_time.cgi*"`
  - `0x43c4d4`: `"date"`
  - `0x43a624`: `"html_response_return_page"`
  - `0x43b6c0`: `"date -s %s "`
  - `0x40fcd0`: `get_cgi("date")`
  - `0x40fcfc`: `get_cgi("html_response_return_page")`
  - `0x40fd2c`: `_system("date -s %s ", user_date)`
