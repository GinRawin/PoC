## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `fcn.004399ac @ 0x4399ac` `atoi(v0) @ 0x4399f4`
- Source位置: `/usr/sbin/uhttpd` `fcn.004399ac @ 0x4399ac` `cgi_value("wl_acl_editnum") @ 0x4399e4`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: ACL 编辑/删除分支直接读取 `wl_acl_editnum` 并调用 `atoi`，字段缺失时 `cgi_value` 返回 `NULL`，后续 `atoi(NULL)` 崩溃。
- 数据包字段 -> 变量赋值:
  - `packet_1.request.prefix + packet_1.request.handler_name -> POST /apply.cgi?ﾌﾃ`
  - `packet_1.body.submit_flag=wlacl_edit -> 进入 ACL 编辑相关路径`
  - `packet_2.request.prefix + packet_2.request.handler_name -> POST /apply.cgi`
  - `packet_2.body.submit_flag=wlacl_del -> 进入同族 ACL 删除路径`
  - `packet_2.body.wl_acl_editnum` 缺失 -> `cgi_value("wl_acl_editnum") @ 0x4399e4` 返回 `NULL`
  - `NULL -> move a0, v0 @ 0x4399f8 -> atoi(a0) @ 0x4399f4`
- 执行顺序:
  1. 第一包先经过普通收尾和子进程刷新逻辑。
  2. 主 trace 后续进入 `0x4399ac` 的 ACL 编辑/删除 helper。
  3. 该函数调用 `cgi_value("wl_acl_editnum")` 读取编辑索引。
  4. 当前样本没有提供该字段，console 打印 `wl_acl_editnum=Unknown`。
  5. 代码继续调用 `atoi(NULL)`，trace 在调用点附近以 `SIGSEGV si_addr=NULL` 结束。

## 原始请求

- 第一包:
  - 方法: `POST`
  - URL: `/apply.cgi?ﾌﾃ`
  - 关键 body: `submit_flag=wlacl_edit`

- 第二包:
  - 方法: `POST`
  - URL: `/apply.cgi`
  - 关键 body: `submit_flag=wlacl_del`

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `trace_summary.json` 显示 `main = 0x4047d4`
- 命中 trace: `trace/usr_sbin_uhttpd.txt`
- 关键 trace:
  - `pc=0x406b60`
  - `19 exit(0)`
  - `pc=0x4399ac`
  - `pc=0x40b514`
  - `pc=0x4399ec`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 关键代码证据

- 字符串表:
  - `wlacl_edit`
  - `wlacl_del`
  - `wl_acl_editnum`

- 反汇编关键点:
  - `0x4399d0`: 加载 `cgi_value`
  - `0x4399dc`: 参数字符串 `wl_acl_editnum`
  - `0x4399e4`: `jalr t9 ; cgi_value`
  - `0x4399ec`: 恢复 `gp`
  - `0x4399f0`: 加载 `atoi`
  - `0x4399f4`: `jalr t9 ; atoi`
  - `0x4399f8`: `move a0, v0`

## 为什么这是确认漏洞

证据已经闭环:

- source: `cgi_value("wl_acl_editnum")`
- variable: `v0`
- sink: `atoi(v0)`
- 运行时证据: `wl_acl_editnum=Unknown` + `SIGSEGV si_addr=NULL`

因此这是 `uhttpd` 内部真实存在的缺字段未判空漏洞。
