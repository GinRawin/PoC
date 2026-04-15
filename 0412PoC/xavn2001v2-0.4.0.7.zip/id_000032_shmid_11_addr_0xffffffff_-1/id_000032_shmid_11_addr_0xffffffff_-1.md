## 摘要

- 判定: 确认漏洞
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用 / DoS
- Source位置: `0x4399d4`，`wlacl_del` handler 内调用 `cgi_value("select_del", ...)`
- Sink位置: `0x4399f4`，调用导入函数 `atoi`；delay slot `0x4399f8` 把 `cgi_value` 返回值放入 `a0`
- 一句话根因: 请求体里的 `submit_flag=wlacl_del` 会选中 `wlacl_del` handler，但该 handler 随后无空值检查地读取 `body.select_del`；当 `select_del` 缺失时，`cgi_value()` 返回 `NULL`，随后在 `0x4399f4` 处进入 `atoi(NULL)` 并崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=apply.cgi?wlacl_edit` -> 原始请求 URL 为 `/apply.cgi?wlacl_edit`
  - `body.submit_flag=wlacl_del` -> `cgi_setobject`(`0x40b95c`) 在 `0x40b9a0` 调用 `cgi_value("submit_flag", ...)`，并在 `0x40b9bc` 把返回值保存到 `s1`
  - `s1="wlacl_del"` -> `0x40ba44`/`0x40ba10` 在分发表 `0x471890` 中命中表项 `0x471b60 { "wlacl_del", 48, 0x4399ac }`，跳转到 `wlacl_del` handler
  - `body.select_del` 缺失 -> `0x4399d4` 调用 `cgi_value("select_del", ...)` 返回 `v0=NULL`
  - `v0=NULL` -> `0x4399f8` 执行 `move a0, v0`，`0x4399f4` 调用 `atoi(a0)`，形成 `atoi(NULL)` sink
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi?wlacl_edit`
  2. `cgi_setobject` 读取 `submit_flag=wlacl_del`
  3. 分发表命中 `wlacl_del -> 0x4399ac`
  4. `wlacl_del` 读取 `select_del`，但该字段不在本次 `VulPacket.json` 的 body 中
  5. `cgi_value("select_del", ...)` 返回 `NULL`
  6. `0x4399f4` 调用 `atoi(NULL)`，随后进程触发 `SIGSEGV si_addr=NULL`

## 请求与入口

- 原始请求 URL: `/apply.cgi?wlacl_edit`
- `body.show_traffic=pls_wait.html`、`body.adr=22222222`、`body.device=22222222` 都只是 body 参数，不是原始 URL。
- 当前请求体中包含 `submit_flag=wlacl_del`，但不包含 `select_del`。
- `trace_summary.json` 将入口进程匹配为 `/usr/sbin/uhttpd`，`main=0x4047d4`。
- `trace/usr_sbin_uhttpd.txt` 显示崩溃仍发生在 `uhttpd` 本体内；虽然中途有 `fork()` 出子进程，但最终 `SIGSEGV` 落在入口 trace 上，没有切到其它可疑二进制。

## Source -> Variable -> Sink 链

1. `cgi_setobject` 分发 `submit_flag`
   - `0x40b95c` 对应符号为 `cgi_setobject`
   - `0x40b9a0`: `a0 = "submit_flag"`，`a1 = s2`，`a2 = s3`
   - `0x40b9ac`: `jal 0x40b4a4`
   - `0x40b4a4` 对应符号为 `cgi_value`，语义是从 CGI 键值表里按名字查值
   - `0x40b9bc`: `move s1, v0`，把 `submit_flag` 对应的值保存到 `s1`

2. `submit_flag` 命中 `wlacl_del` 分发表项
   - `0x40ba44` 从 `0x471890` 开始遍历 `{name_ptr, bitmap_idx, handler_ptr}` 表
   - 表项 `0x471b60` 为 `{ 0x44e334 "wlacl_del", 48, 0x4399ac }`
   - `0x40ba10` 取出 `t9 = *(s0+8)` 并 `jalr t9`，把执行流送到 `0x4399ac`
   - 这一步证明真正进入漏洞函数的控制输入来自 `body.submit_flag=wlacl_del`

3. `wlacl_del` 读取真实漏洞 source: `select_del`
   - `0x4399ac` 是被命中的 handler 入口
   - `0x4399d4`: `a0 = "select_del"`，`a1 = s1`，`a2 = s2`
   - `0x4399e4`: `jalr t9`，其中 `t9 = 0x40b4a4 (cgi_value)`
   - 本次 `VulPacket.json` 的 body 不含 `select_del`，因此这里的返回值只能是 `NULL`

4. `NULL` 直接进入 `atoi`
   - `0x4399f0`: `t9 = 0x44b6d0`
   - 动态符号解析表明 `0x44b6d0 = atoi`
   - `0x4399f4`: `jalr t9`
   - `0x4399f8`: delay slot 执行 `move a0, v0`
   - 因此 callsite 实参是 `a0 = NULL`，真实 sink 为 `atoi(NULL)`

## 关键证据

- `VulPacket.json`
  - 原始请求是 `POST /apply.cgi?wlacl_edit`
  - body 中存在 `submit_flag=wlacl_del`
  - body 中不存在 `select_del`

- `trace/usr_sbin_uhttpd.txt`
  - `690: pc=0x40b95c` -> 进入 `cgi_setobject`
  - `701: pc=0x40b9e4` -> `cgi_value("submit_flag", ...)`
  - `708: pc=0x40ba40`
  - `710: pc=0x40ba10` -> 命中 handler 并调用 `0x4399ac`
  - `711: pc=0x4399ac` -> 进入 `wlacl_del`
  - `713: pc=0x4399ec` -> `cgi_value("select_del", ...)` 返回后的基本块起点
  - `714: --- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

- `container.console.log`
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `[GreenHouseQEMU] SIG 11`

- 符号与常量核验
  - `0x40b4a4 = cgi_value`
  - `0x40b95c = cgi_setobject`
  - `0x44b6d0 = atoi`
  - `0x44e334 = "wlacl_del"`
  - `0x45d3b0 = "select_del"`

## 结论

- 这是一个可闭环的真实崩溃链，不再是“内部 ACL/NVRAM 状态为空”的泛化推测。
- `submit_flag` 负责把请求导向 `wlacl_del` handler，但真正进入 sink 的 source 是缺失的 `select_del`。
- 由于 `wlacl_del` 在 `cgi_value("select_del", ...)` 之后没有做空值检查，`NULL` 被直接送入 `atoi`，与 trace 中的 `si_addr=NULL` 完整一致。
- 因此本 case 应更新为 `确认漏洞`。
