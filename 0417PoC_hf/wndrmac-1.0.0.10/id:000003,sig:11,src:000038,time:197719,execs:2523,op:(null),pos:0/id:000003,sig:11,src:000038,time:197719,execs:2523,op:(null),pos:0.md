# 漏洞分析: wndrmac-1.0.0.10 / id:000003,sig:11,src:000038,time:197719,execs:2523,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `uhttpd do_file@0x409530 sink@0x409564 (jalr sprintf)`
- Source位置: `uhttpd handle_request@0x40c168 source@0x40c2a8 (strsep 提取 request URI token)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `栈缓冲区溢出 / 返回地址覆盖`
- 一句话根因: `do_file()` 将未校验长度的请求路径用 `sprintf("/www/%s", path)` 写入栈上 `sp+0x18` 缓冲区，覆盖了 `sp+0xa0` 的保存返回地址，返回时跳到 `0x61616160` 崩溃。
- 数据包字段 -> 变量赋值:
  - `request.handler_name` -> `handle_request` 中 URI token 指针 `s2`
  - `request.handler_name` -> `do_file(a0)` -> 栈缓冲区 `sp+0x18`
  - `request.method=GET` -> `handle_request` 中方法分支，允许走静态文件处理分支
  - `request.handler_name` 末尾 `.gif` -> 命中 `mime_handlers` 表项，`s3[0x10]` 装载为 `do_file@0x409530`
- 执行顺序:
  1. `handle_request` 用 `fgets` 读取请求行，再用 `strsep` 切出 URI token，得到攻击者控制的 `handler_name`。
  2. `handle_request` 遍历 `mime_handlers`，根据 URI 与表项匹配，最终在 `0x40d840` 取出函数指针并调用 `do_file(s2, s4)`。
  3. `do_file` 在 `0x409564` 调用 `sprintf(sp+0x18, "/www/%s", a0)`，把 266 字节字符串写入仅距保存 `ra` 136 字节的位置；随后返回路径在 `0x40962c` 取出被污染的 `ra`，跳转到 `0x61616160` 触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/usr/sbin/uhttpd`
- Main地址: `unknown`
- 命中的入口trace: `trace/entry_trace.txt`
- 子进程trace链: `无，crash 发生在入口二进制自身`
- 关键pc地址:
  - `0x40d840` `lw t9, 0x10(s3)`，从 handler 表取函数指针
  - `0x40d84c` 调用实参准备，`a0=s2`
  - `0x409530` 进入 `do_file`
  - `0x409564` 调用 `sprintf`
  - `0x40962c` 返回路径开始恢复保存寄存器
  - `si_addr=0x61616160`，符合返回地址被 `'a'` 覆盖后的崩溃模式

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `request.handler_name` 控制 `handle_request` 中的 URI token，之后被保存在 `s2`
  - `request.method` 控制 `strcasecmp(method, "post")` 的结果；当前为 `GET`，未走 POST 专用分支
  - `request.handler_name` 中的 `.gif` 控制 handler 选择，使 `s3[0x10]` 指向 `do_file`
- 哪个函数读取了source字段:
  - `handle_request@0x40c1d8` 用 `fgets` 读取整行请求
  - `handle_request@0x40c248` / `0x40c2a8` 连续 `strsep` 切分请求行，第二个 token 即 URI
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - `do_file@0x409558-0x409564`：`a0=sp+0x18`，`a1="/www/%s"`，`a2=用户URI`，随后 `jalr t9` 调用 `sprintf`
- 最终如何到达sink:
  - `request.handler_name`
  - `-> handle_request` 读取并切分请求行
  - `-> URI token/s2`
  - `-> 0x40d84c` 作为 `do_file(a0)` 实参传递
  - `-> 0x409564 sprintf(sp+0x18, "/www/%s", a0)`
  - `-> 覆盖保存 ra`
  - `-> 0x40962c` 返回时取出坏 ra，跳到 `0x61616160`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。崩溃不是单纯“文件不存在”或仿真噪声，而是与请求中的长路径直接对应的返回地址覆盖。`si_addr=0x61616160` 与样本中大量 `'a'` 完全一致，且崩溃路径精确落在 `sprintf` 之后、函数返回之前。
- 当前缺失的证据:
  - 未直接导出运行时寄存器/栈快照，因此没有逐字节展示被覆盖后的 `ra` 栈内容。
- 对当前现象的替代解释:
  - 最合理的替代解释是“`do_file` 内部其他对象指针损坏导致异常返回”；但结合 `sprintf` 的无界写、`handler_name` 长度 261、`sp+0x18` 到 `ra` 偏移仅 136 字节，以及返回目标呈现 `0x61616160`，替代解释不成立。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt` / `trace/usr_sbin_uhttpd.txt` 末尾:
    - `pc=0x40d840`
    - `pc=0x40d84c`
    - `pc=0x409530`
    - `pc=0x40956c`
    - `pc=0x409584`
    - `pc=0x40962c`
    - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x61616160} ---`
- 关键容器日志行:
  - `container.console.log`:
    - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
    - `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `handle_request@0x40d548-0x40d560`: 遍历 `mime_handlers`，以 `strstr(s2, s1)` 用 URI 匹配表项
  - `handle_request@0x40d840-0x40d850`: `lw t9, 0x10(s3)` 后调用，trace 实际跳到 `0x409530`，说明命中 `do_file`
  - `do_file@0x409558-0x409564`: `a0=sp+0x18`，`a1="/www/%s"`，`a2=用户路径`，调用 `sprintf`
  - `do_file@0x409540`: 保存 `ra` 到 `sp+0xa0`
  - `do_file@0x40962c-0x409638`: 从 `sp+0xa0` 恢复 `ra` 并返回；缓冲区 `sp+0x18` 到保存 `ra` 的距离为 `0x88` 字节，仅 136 字节
  - `VulPacket.json`: `request.handler_name` 长度为 `261`，拼接 `/www/` 后总长 `266`，足以越过 `ra`
