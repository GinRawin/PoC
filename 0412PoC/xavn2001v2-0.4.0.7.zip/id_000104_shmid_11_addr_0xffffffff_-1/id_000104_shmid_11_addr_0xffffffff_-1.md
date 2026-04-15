## 摘要

- 判定: 确认漏洞
- 漏洞二进制: /usr/sbin/uhttpd
- 漏洞类型: 空指针解引用 / 拒绝服务
- Source位置: /usr/sbin/uhttpd 0x439820 `cgi_value("acl_wps_disable", ...)`
- Sink位置: /usr/sbin/uhttpd 0x439844 `strcmp(v0, "1")`
- 一句话根因: `submit_flag=wlacl_apply` 命中 `0x471b6c` 的分发表项后进入 `0x4397a0`，当请求里同时缺少 `wl_access_ctrl_on` 和 `acl_wps_disable` 时，代码把 `cgi_value("acl_wps_disable")` 的 `NULL` 返回值直接作为 `strcmp()` 第一个实参，导致 `SIGSEGV si_addr=NULL`。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=apply.cgi?debuginfo.htm` -> 原始请求 URL 为 `/apply.cgi?debuginfo.htm`
  - `body.submit_flag=wlacl_apply` -> `0x40b9a8` 的 `cgi_value("submit_flag", ...)` 返回 `"wlacl_apply"` -> `0x40ba44` 的分发表逐项 `strcmp` -> 命中 `0x471b6c = [0x44e340 "wlacl_apply", 0xd, 0x4397a0]` -> `0x40ba30` `jalr t9` 调入 `0x4397a0`
  - `body.wl_access_ctrl_on` 缺失 -> `0x4397dc` 的 `cgi_value("wl_access_ctrl_on", ...)` 返回 `NULL` -> `0x4397e8` `beqz v0, 0x43981c`
  - `body.acl_wps_disable` 缺失 -> `0x43982c` 的 `cgi_value("acl_wps_disable", ...)` 返回 `NULL` -> `0x43983c` `move a0, v0`
  - 常量 `"1"` -> `0x4516f0` -> `0x439848` `addiu a1, s1, 0x16f0`
  - `a0=NULL`, `a1="1"` -> `0x439844` `jalr t9` 调用 `strcmp` -> 空指针解引用崩溃
- 执行顺序:
  1. `/usr/sbin/uhttpd` 接收 `POST /apply.cgi?debuginfo.htm`。
  2. trace 在 `0x40b95c` 进入 `cgi_setobject()`，`0x40b9a8` 读取 `submit_flag`。
  3. `0x40ba44..0x40ba50` 在线性表中比较 `"wlacl_apply"`，`0x40ba10/0x40ba20/0x40ba30` 从表项 `0x471b6c` 取出 handler 并跳到 `0x4397a0`。
  4. `0x4397dc` 读取 `wl_access_ctrl_on` 失败，`0x4397e8` 分支跳到 `0x43981c`。
  5. `0x43982c` 再读取 `acl_wps_disable`，返回 `NULL`。
  6. `0x439844` 调用 `strcmp(NULL, "1")`，随后 trace 记录 `SIGSEGV {si_addr=NULL}`，console 记录 `SIG 11`。

## 请求与入口

- `VulPacket.json.request` 明确原始请求是 `POST /apply.cgi?debuginfo.htm`。
- `body.show_traffic=upgrade_check_free.cgi` 只是 body 参数，不是原始 URL。
- 入口进程是 `/usr/sbin/uhttpd`，`main=0x4047d4`，命中 trace 为 `trace/usr_sbin_uhttpd.txt`。
- 本次崩溃发生在入口进程自身，而不是 fork 后的子进程:
  - `trace/usr_sbin_uhttpd.txt` 在 340-345 行出现过 `fork()`，但最终异常发生在同一份入口 trace 的 716 行。
  - `trace/9_tb_log.txt` 只记录了 `9 exit(0)`，不是崩溃进程。

## 关键证据

- 请求分派:
  - `0x40b9a8`: `cgi_value("submit_flag", ...)`
  - `0x40ba44`: 从 dispatch table 取表项字符串并与 `submit_flag` 比较
  - `0x471b6c`: `0x44e340, 0x0000000d, 0x4397a0`
  - `0x44e340`: `"wlacl_apply"`
  - `0x40ba30`: `jalr t9`，用表项中的函数指针调用 `0x4397a0`
- 漏洞调用点:
  - `0x4397d4`: 装载 `"wl_access_ctrl_on"`
  - `0x4397dc`: `cgi_value("wl_access_ctrl_on", ...)`
  - `0x4397e8`: `beqz v0, 0x43981c`
  - `0x439828`: 装载 `"acl_wps_disable"`
  - `0x43982c`: `cgi_value("acl_wps_disable", ...)`
  - `0x43983c`: `move a0, v0`
  - `0x439840`: 装载 `strcmp`
  - `0x439848`: 装载常量 `"1"`
  - `0x439844`: `jalr t9` 调用 `strcmp`
- trace / console 闭环:
  - `trace/usr_sbin_uhttpd.txt:690-710` 命中 `cgi_setobject()` 和 dispatch 逻辑
  - `trace/usr_sbin_uhttpd.txt:711` 命中 `0x4397a0`
  - `trace/usr_sbin_uhttpd.txt:713` 命中 `0x4397e4`
  - `trace/usr_sbin_uhttpd.txt:714` 命中 `0x43981c`
  - `trace/usr_sbin_uhttpd.txt:715` 命中 `0x439834`
  - `trace/usr_sbin_uhttpd.txt:716` 记录 `SIGSEGV {si_addr=NULL}`
  - `container.console.log:23-24` 记录 `SIGSEGV CAUGHT` 和 `SIG 11`

## Source -> variable -> sink 链

- 分派 source:
  - `submit_flag` 的真实读取点是 `0x40b9a8`，不是由日志或旧报告推断。
  - `cgi_setobject()` 在 `0x40ba44..0x40ba50` 对每个表项执行 `strcmp(entry->name, submit_flag)`。
  - 表项 `0x471b6c` 明确是 `[ "wlacl_apply", 0xd, 0x4397a0 ]`，因此当前请求确实进入 `wlacl_apply` handler。
- 漏洞 source:
  - `0x439820..0x439830` 真实读取的 CGI 键名是 `"acl_wps_disable"`。
  - 该字段不在 `VulPacket.json.body` 里，所以当前请求下 `cgi_value("acl_wps_disable", ...)` 的最合理返回是 `NULL`。
  - 上一层 `0x4397dc` 读取 `"wl_access_ctrl_on"` 也缺失，因此 `0x4397e8` 会走到 `0x43981c` 的 fallback 路径。
- 变量传递:
  - 第二次 `cgi_value()` 的返回值保存在 `v0`。
  - `0x43983c` 直接执行 `move a0, v0`，没有任何 `NULL` 检查。
  - `0x439848` 同时把常量 `"1"` 放入 `a1`。
- sink:
  - `0x439840` 从 GOT 取 `strcmp`。
  - `0x439844` 执行 `jalr t9`，此时实参是 `a0=NULL`, `a1="1"`。
  - `strcmp(NULL, "1")` 与 trace/console 里的 `si_addr=NULL` 完全一致。

## 为什么是确认漏洞

- 这是一个可解释的、与 trace 一致的空指针解引用:
  - source 可解释: `body.acl_wps_disable` 缺失，调用点已核验。
  - sink 可解释: `strcmp` 调用点已核验，且第一个参数直接来自 `cgi_value()` 的返回寄存器。
  - `source -> variable -> sink` 数据流可解释: `cgi_value("acl_wps_disable") -> v0 -> a0 -> strcmp`
  - 执行顺序与异常现象闭环: `submit_flag` 分派 -> `0x4397a0` -> 缺字段 -> `strcmp(NULL, "1")` -> `SIGSEGV`
- 这不是仅靠字符串或旧报告得到的推测，关键字段名、常量、分支和函数指针都回到了真实 callsite 核验。
- 因为崩溃由攻击者可控请求缺失必需字段触发，所以本 case 不应再归为 `证据不足`。

## 误报解释排除

- 不是 `show_traffic=upgrade_check_free.cgi` 触发:
  - 原始 URL 由 `VulPacket.json.request` 决定，是 `/apply.cgi?debuginfo.htm`。
  - `show_traffic` 只是 body 参数，且当前崩溃链条没有读取它。
- 不是缓冲区溢出或命令执行:
  - 崩溃点的真实 sink 是 `strcmp`，不是 `strcpy`、`sprintf`、`system` 或 shell 调用。
  - `si_addr=NULL` 与空指针解引用吻合，不符合覆盖返回地址或命令注入的形态。
- 不是子进程误关联:
  - 崩溃信号直接记录在入口 trace `trace/usr_sbin_uhttpd.txt`，没有转移到 `trace/9_tb_log.txt`。
