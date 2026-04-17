# 漏洞分析: r6900-v1.0.2.26-10.0.45 / id:000004,shmid:000003,cmdinj,src:000521,time:17352290,execs:344472,op:splice,rep:8,ipc:3

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/lib/libacos_shared.so sym.send_data 0x000323a4 (system)`
- Source位置: `/usr/sbin/httpd handler@0x000ca2ac, source read@0x000ca2e0 ("country") / 0x000ca320 ("purchase_date")`
- 漏洞二进制: `/usr/sbin/httpd`, `/lib/libacos_shared.so`
- 漏洞类型: `命令注入`
- 一句话根因: `bd_genie_prodcut_register.cgi` 将请求体中的 `country` / `purchase_date` 写入连续缓冲区后交给 `sso_product_register`，后者把这两个字段拼进 JSON，再由 `send_data` 直接格式化进 `curl ... -d '%s'` 的 shell 命令并调用 `system()`，没有做 shell 转义。
- 数据包字段 -> 变量赋值:
  - `body.country` -> `httpd` 栈缓冲区 `[sp+0x1608]`，随后作为 `sso_product_register(arg1 + 0x200)` 的 `countryPurchased`
  - `body.purchase_date` -> `httpd` 栈缓冲区 `[sp+0x1508]`，随后作为 `sso_product_register(arg1 + 0x100)` 的 `dateOfPurchase`
  - `request.handler_name=bd_genie_prodcut_register.cgi` -> 命中 `httpd` CGI 表 `0x001618c8 -> 0x000ca2ac`
- 执行顺序:
  1. HTTP POST `/bd_genie_prodcut_register.cgi` 命中 `httpd` 中的 handler `0x000ca2ac`
  2. handler 读取 `country` 和 `purchase_date`，与本机 `serialNumber` 组织成一块连续内存并调用 `sso_product_register`
  3. `sso_product_register` 用 `snprintf` 生成 `{"serialNumber":"%s","dateOfPurchase":"%s","countryPurchased":"%s"}`，再传给 `send_data`
  4. `send_data` 用 `snprintf` 生成 `curl -k --insecure -X POST %s ... -d '%s' ...`，最后在 `0x000323a4` 调用 `system()`

## Trace映射

- 入口二进制: `/usr/sbin/httpd`
- Main地址: `unknown`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `101 fork() = 104 -> 104 exit(0)`
- 关键pc地址:
  - `httpd CGI表项: 0x001618c8 -> 0x000ca2ac`
  - `httpd source读取: 0x000ca2e0, 0x000ca320`
  - `libacos_shared.so sso_product_register: 0x0003388c`
  - `libacos_shared.so JSON拼接: 0x0003391c`
  - `libacos_shared.so curl命令拼接: 0x000323d8 / 0x0003238c`
  - `libacos_shared.so sink(system): 0x000323a4`

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `body.country` 由 `httpd@0x000ca2d8-0x000ca2e0` 读取，先落到临时缓冲区 `r4=[sp+0x808]`，随后 `strcpy` 到 `[sp+0x1608]`
  - `body.purchase_date` 由 `httpd@0x000ca314-0x000ca320` 读取，先落到临时缓冲区 `r4=[sp+0x8]`，随后 `strcpy` 到 `[sp+0x1508]`
  - `body.country` / `body.purchase_date` 分别成为 `sso_product_register` 中 `arg1+0x200` / `arg1+0x100`
- 哪个函数读取了source字段:
  - `httpd@0x000ca2ac` 对应的 `bd_genie_prodcut_register.cgi` handler
  - 读取动作在 `0x000ca2e0` 和 `0x000ca320`，调用本地函数 `fcn.0001a3b8` 按键名取值
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `libacos_shared.so:sso_product_register@0x0003391c`:
    - `r3 = arg1` -> `serialNumber`
    - `[sp] = arg1+0x100` -> `dateOfPurchase`
    - `[sp+4] = arg1+0x200` -> `countryPurchased`
    - 格式串为 `{"serialNumber": "%s", "dateOfPurchase": "%s", "countryPurchased": "%s"}`
  - `libacos_shared.so:send_data@0x000323d8`:
    - 将上一步生成的 JSON 作为 `%s` 填进 `curl -k --insecure -X POST %s ... -d '%s' -o %s --connect-timeout %d`
- 最终如何到达sink:
  - `country` / `purchase_date`
  - -> `httpd` 栈上连续块 `[serial][purchase_date][country]`
  - -> `sso_product_register` 生成 `sso_body`
  - -> `send_data` 生成完整 shell 命令字符串到 `[sp+0x18]`
  - -> `system([sp+0x18]) @ 0x000323a4`
  - 由于 JSON 被放进单引号包围的 `-d '%s'` 中，只要任一可控字段包含单引号即可突破 shell quoting，形成命令注入

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这不是崩溃误报。虽然本次运行未出现 `SIGSEGV/SIGABRT`，但二进制级数据流已经闭合到真实危险 sink：外部可控请求字段进入 `system()` 命令模板，且中间没有 shell 转义或避免 shell 的实现。
  - `container.console.log` 同时给出了运行时侧证：打印了 `sso_body=...countryPurchased...`，随后出现 `[qemu] doing qemu_execven on filename /bin/sh` 与 `/sbin/curl`，与 `send_data` 的 `system("curl ...")` 逻辑一致。
- 当前缺失的证据:
  - 当前样本中的 `country` / `purchase_date` 没有包含单引号，日志里也没有直接打印最终 `send data cmd=[...]`，因此没有看到“任意附加命令已执行”的现象证据。
- 对当前现象的替代解释:
  - 当前观测到的 `sso_productregister parse data fail..` 和 `Timeout`，更直接的解释是云端返回异常或返回体无法解析；这解释了“为什么这次没有崩溃/没有明显命令执行回显”，但不能否定已确认的 source-to-system 注入链。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt`: `101 fork() = 104`, `101 exit(0)`
  - `trace/104_tb_log.txt`: `104 exit(0)`
- 关键容器日志行:
  - `Product Register...`
  - `sso_body={"serialNumber": "", "dateOfPurchase": "", "countryPurchased": "aaaWZQ..."}`
  - `sso_productregister parse data fail..`
  - `Login fail status=0, message=Timeout, code=, error_code=`
  - `[qemu] doing qemu_execven on filename /bin/sh`
  - `[qemu] doing qemu_execven on filename /sbin/curl`
- 关键反编译证据:
  - `httpd@0x001618c8`: CGI 表中 `bd_genie_prodcut_register.cgi -> 0x000ca2ac`
  - `httpd@0x000ca2dc/0x000ca318`: 分别加载字符串 `country` / `purchase_date`
  - `httpd@0x000ca2f8` 与 `0x000ca338`: `strcpy` 把 source 写入连续栈块
  - `httpd@0x000ca344`: 调用 `sso_product_register`
  - `libacos_shared.so@0x00033910-0x0003391c`: 以 `serial/date/country` 三个 `%s` 生成 JSON
  - `libacos_shared.so@0x000323d0-0x000323d8`: 以 `-d '%s'` 生成 curl shell 命令
  - `libacos_shared.so@0x000323a4`: `system()` 执行该命令
