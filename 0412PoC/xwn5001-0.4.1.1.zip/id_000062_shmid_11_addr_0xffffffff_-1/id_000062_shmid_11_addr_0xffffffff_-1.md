## 摘要

- 判定: 确认漏洞
- Sink位置: `/usr/sbin/uhttpd` `fcn.004397a0 @ 0x4397a0` `strcmp(v0, "0") @ 0x439844`
- Source位置: `/usr/sbin/uhttpd` `fcn.004397a0 @ 0x4397a0` `cgi_value("acl_wps_disable") @ 0x43982c`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 内存破坏
- 一句话根因: `wlacl_apply` 处理函数会读取 `acl_wps_disable`，但没有检查 `cgi_value` 返回值是否为 `NULL`，随后直接把它传给 `strcmp`，缺失该字段时触发空指针解引用。
- 数据包字段 -> 变量赋值:
  - `packet_1.request.prefix + packet_1.request.handler_name -> POST /apply.cgi?upgrade_check_free.cgi`，这是原始请求 URL
  - `packet_1.body.submit_flag=wlacl_apply -> cgi_setobject @ 0x40b95c / cgi_value("submit_flag") @ 0x40b9ac -> 进入 wlacl_apply handler @ 0x4397a0`
  - `packet_1.body.wl_access_ctrl_on` 缺失 -> `cgi_value("wl_access_ctrl_on") @ 0x4397dc` 返回 `NULL`，分支直接跳到后续逻辑
  - `packet_1.body.acl_wps_disable` 缺失 -> `cgi_value("acl_wps_disable") @ 0x43982c` 返回 `NULL` -> `a0 = v0(NULL) @ 0x43983c`
  - `a0(NULL) -> strcmp(a0, "0") @ 0x439844 -> SIGSEGV`
- 执行顺序:
  1. `/usr/sbin/uhttpd` 在 `main @ 0x4047d4` 对应 trace 中接收 `POST /apply.cgi?upgrade_check_free.cgi`。
  2. `cgi_setobject` 读取 `submit_flag=wlacl_apply`，将请求分发到 `fcn.004397a0`。
  3. 该函数先读取 `wl_access_ctrl_on`；字段缺失时走 `0x43981c` 的分支继续执行。
  4. 随后函数在 `0x43982c` 读取 `acl_wps_disable`，但没有检查返回值是否为空。
  5. 返回值被直接送入 `strcmp`，trace 在 `0x439834` 后立刻以 `SIGSEGV si_addr=NULL` 结束。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?upgrade_check_free.cgi`
- URL 来源: `VulPacket.json` 的 `packet_1.request.prefix` 与 `packet_1.request.handler_name`
- 说明: `device`、`adr` 等只是 body 参数；本次真实触发崩溃的是 `submit_flag=wlacl_apply` 选中的 ACL 处理路径，以及缺失的 ACL 配置字段

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `trace_summary.json` 显示 `main = 0x4047d4`
- 命中 trace: `trace/usr_sbin_uhttpd.txt`
- 关键 trace 片段:
  - `pc=0x40b95c`
  - `pc=0x4397a0`
  - `pc=0x4397e4`
  - `pc=0x43981c`
  - `pc=0x439834`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`

## 从输入到漏洞点的数据流

`wlacl_apply` 对应的处理函数 `fcn.004397a0` 会依次读取两个 CGI 字段:

- `wl_access_ctrl_on`
- `acl_wps_disable`

从当前样本的 `VulPacket.json` 看，这两个字段都不存在。第一处读取 `wl_access_ctrl_on` 之后有判空分支，所以只是跳过一次 `nvram_set`。第二处读取 `acl_wps_disable` 之后却直接进入字符串比较逻辑:

- `0x43982c`: `jal sym.cgi_value` 读取 `acl_wps_disable`
- `0x43983c`: `move a0, v0`
- `0x439840`: 加载 `strcmp`
- `0x439844`: `jalr t9`

如果 `v0 == NULL`，那么 `strcmp(NULL, "0")` 会在 libc 内部解引用空指针。trace 的终点正好落在这段路径上，console 也没有任何其他外部命令失败信息来干扰判断，因此这是明确的参数缺失型空指针崩溃。

## 关键反汇编证据

- `0x4397d4`: 参数字符串 `wl_access_ctrl_on`
- `0x4397dc`: `jal sym.cgi_value`
- `0x4397e8`: `beqz v0, 0x43981c`
- `0x439828`: 参数字符串 `acl_wps_disable`
- `0x43982c`: `jal sym.cgi_value`
- `0x43983c`: `move a0, v0`
- `0x439844`: `jalr t9 ; strcmp`
- 字符串表:
  - `0x46e9b0 -> wl_access_ctrl_on`
  - `0x46e9d8 -> acl_wps_disable`
  - `0x4516d0 -> "0"`

## 为什么这是确认漏洞

这条链已经闭环:

- source 可解释: `cgi_value("acl_wps_disable") @ 0x43982c`
- sink 可解释: `strcmp(NULL, "0") @ 0x439844`
- 数据流可解释: 缺失字段导致 `v0 == NULL`，该值原样进入 `a0`
- trace 与反汇编一致: `0x4397a0 -> 0x43981c -> 0x439834 -> SIGSEGV NULL`

因此这不是环境噪声，也不是普通脚本失败，而是 `uhttpd` 中真实存在的未判空缺陷。
