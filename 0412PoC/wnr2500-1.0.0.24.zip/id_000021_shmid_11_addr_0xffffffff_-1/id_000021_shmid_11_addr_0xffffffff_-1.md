## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd 0x446140 0x4461e0`
- Source位置: `/usr/sbin/uhttpd 0x446140 0x4461cc`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `参数校验缺失`
- 一句话根因: `submit_flag=delete_acc` 进入访问控制删除回调后，程序对 `body.hidden_del_num` 的 `cgi_value` 返回值缺少 NULL 检查，直接传给 `atoi`，最终触发空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` + `request.prefix=/` + `request.handler_name=apply.cgi?acc_control_allow` -> 原始请求 URL 为 `/apply.cgi?acc_control_allow`
  - `body.submit_flag=delete_acc` -> `cgi_setobject @ 0x40b4bc` 读取后命中 `delete_acc` 动作表项，跳转到 `0x446140`
  - `body.hidden_del_list` 缺失 -> `cgi_value("hidden_del_list") @ 0x4461ac` 返回候选 `NULL`
  - `body.hidden_del_num` 缺失 -> `cgi_value("hidden_del_num") @ 0x4461cc` 返回 `NULL` -> `atoi @ 0x4461e0` 的 `arg0`
  - `body.hidden_change_num=1` / `body.hidden_change_list=1` -> 属于另一条 access-control 变更分支，本函数不读取
- 执行顺序:
  1. `uhttpd` 接收 `POST /apply.cgi?acc_control_allow`
  2. `cgi_setobject` 读取 `submit_flag=delete_acc`，把请求分派到删除访问控制项的回调 `0x446140`
  3. 该函数先调用 `do_setting`，然后查询 `hidden_del_list` 与 `hidden_del_num`
  4. 当前样本没有提供 `hidden_del_num`，`cgi_value` 返回 `NULL`
  5. 程序仍在 `0x4461e0` 调用 `atoi(NULL)`，trace 随后出现 `SIGSEGV si_addr=NULL`

## 原始请求还原

- 原始请求方法: `POST`
- 原始 URL: `/apply.cgi?acc_control_allow`
- handler 来源: `VulPacket.json.packet_1.request.handler_name=apply.cgi?acc_control_allow`
- 虽然 query 看起来像 `acc_control_allow`，但本次实际进入的动作由 `body.submit_flag=delete_acc` 决定
- `body.hidden_change_num`、`body.hidden_change_list` 只是请求体参数，不是 URL，也不是本分支实际读取的字段

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `binary_summary.json` 给出的 `main` 地址: `0x4040b8`
- `trace_summary.json` 已匹配到 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 序列:
  - `pc=0x40b46c` 进入 `cgi_setobject`
  - `pc=0x446140` 进入访问控制删除回调
  - `pc=0x409b18 ... 0x409bb4` 执行 `do_setting`
  - `pc=0x446198 -> 0x409d20 -> 0x4461b4` 返回第一次 `cgi_value`
  - `pc=0x4461d4 -> 0x44aac0` 把第二次 `cgi_value` 结果传给 `atoi`
  - 随后 `SIGSEGV si_addr=NULL`

## 关键数据流

- `cgi_setobject @ 0x40b46c` 通过 `cgi_value("submit_flag") @ 0x40b4bc` 取得 `delete_acc`
- trace 在动作表匹配后落到 `0x446140`，说明本次实际执行的是 `delete_acc` 回调，而不是 query 字面上的 `acc_control_allow`
- `0x4461ac` 调用 `cgi_value("hidden_del_list")`
- `0x4461cc` 调用 `cgi_value("hidden_del_num")`
- `rabin2 -zz` 对应字符串:
  - `0x463994`: `hidden_del_list`
  - `0x4639a4`: `hidden_del_num`
- 当前 `VulPacket.json.body` 不包含 `hidden_del_list` 和 `hidden_del_num`
- 程序没有对第二次查询结果做 NULL 检查，而是在 `0x4461e0` 直接调用 `atoi`

## 关键证据

- `VulPacket.json` 中存在 `submit_flag=delete_acc`，但缺失 `hidden_del_list` / `hidden_del_num`
- 同一数据包虽然含有 `hidden_change_num=1` 与 `hidden_change_list=1`，但二进制当前回调实际读取的是 `hidden_del_*`，不是 `hidden_change_*`
- `objdump` / `radare2` 反汇编显示:
  - `0x4461ac` 调用 `cgi_value("hidden_del_list")`
  - `0x4461cc` 调用 `cgi_value("hidden_del_num")`
  - `0x4461e0` 调用 `atoi`
- `rabin2 -i` 显示 `0x44aac0` 为 `atoi`
- trace 在 `0x44aac0` 后立刻触发 `SIGSEGV si_addr=NULL`

## 结论

- 这是一个可解释的请求体参数校验缺失漏洞
- 闭环已经成立:
  - `body.submit_flag=delete_acc`
  - `body.hidden_del_num` 缺失
  - `cgi_value("hidden_del_num") @ 0x4461cc`
  - `atoi @ 0x4461e0`
  - `SIGSEGV si_addr=NULL`

## 命中benchmark:是

## 0-day:是
