## 摘要

- 判定: 确认漏洞
- Sink位置: /usr/sbin/uhttpd 0x43a5e0 0x43a858
- Source位置: /usr/sbin/uhttpd 0x43a5e0 0x43a800
- 漏洞二进制: /usr/sbin/uhttpd
- 漏洞类型: 内存破坏
- 一句话根因: `config_lan_group` 将未限长的 `body.group_num` 直接带入 `sprintf("lan%s_ipaddr", group_num)`，把 `sp+0x50` 的栈缓冲区溢出到后续局部变量槽位，进而把后续 `nvram_set` 使用的指针破坏成攻击者数据。
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.prefix=/`, `request.handler_name=apply.cgi?wlacl_add` -> 原始请求 URL 为 `/apply.cgi?wlacl_add`
  - `body.submit_flag=lan_group` -> `cgi_setobject(0x40b95c)` 选择 `config_lan_group(0x43a5e0)` 处理路径
  - `body.group_num` -> `s4` (`cgi_value("group_num")` 返回值) -> `sprintf` arg#3 at `0x43a844` -> 栈缓冲区 `sp+0x50`
  - `body.lan_ipaddr` -> 保存到 `sp+0x70`，原本作为后续 `nvram_set` 的 value 指针；被前述 `sprintf` 溢出覆盖为 `0x3232325f`
- 执行顺序:
  1. `/apply.cgi?wlacl_add` 进入 `uhttpd` 的 `apply.cgi` 分发逻辑。
  2. `cgi_setobject(0x40b95c)` 读取 `body.submit_flag=lan_group`，转入 `config_lan_group(0x43a5e0)`。
  3. `config_lan_group` 在 `0x43a800` 读取 `body.group_num`，并在 `0x43a820` 先把它写到 NVRAM 键 `lan_group_num`。
  4. 同函数在 `0x43a858` 调用 `sprintf(sp+0x50, "lan%s_ipaddr", group_num)`，因 `group_num` 过长覆盖到 `sp+0x70`。
  5. 覆盖后的 `sp+0x70` 被 `0x43a86c` 的 `nvram_set` 当作 value 指针使用，trace 在 `0x43a860` 后直接收到 `SIGSEGV si_addr=0x3232325f`。

## 请求与入口

- `VulPacket.json.request` 显示原始请求为 `POST /apply.cgi?wlacl_add`。
- 真正决定配置分支的是 `body.submit_flag=lan_group`，不是 query 中的 `wlacl_add`。
- `trace_summary.json` 将入口二进制匹配为 `/usr/sbin/uhttpd`，`main=0x4047d4`，命中 trace 为 `trace/usr_sbin_uhttpd.txt`。
- 入口 trace 在第 16 行命中 `pc=0x4047d4`；后续在第 690 行进入 `cgi_setobject(0x40b95c)`，第 711 行进入 `config_lan_group(0x43a5e0)`。

## 关键地址与数据流

- `0x43a630` 打印字符串 `config_lan_group`，与控制台日志中的同名输出一致，确认崩溃函数。
- `0x43a7f8` / `0x43a800` 调用 `cgi_value("group_num", ...)`，把 `body.group_num` 读入 `s4`。
- `0x43a818` / `0x43a824` 调用 `nvram_set("lan_group_num", group_num)`。
- `0x43a83c` 载入格式串 `lan%s_ipaddr`，`0x43a858` 调用 `sprintf(sp+0x50, "lan%s_ipaddr", s4)`。
- 栈布局显示目标缓冲区从 `sp+0x50` 开始，而下一槽位在 `sp+0x70`。二者仅相隔 `0x20` 字节。
- 当前样本中 `body.group_num` 为 32 个 `2`。格式化结果 `lan222...222_ipaddr` 长度超过 32 字节，前 4 个越界字节恰好是 `0x32 0x32 0x32 0x5f`，即大端值 `0x3232325f`。
- `0x43a86c` 调用 `nvram_set` 前，从 `sp+0x70` 取 value 指针作为 `a1`。该槽位已被前述越界写破坏，因此在后续解引用时崩溃。

## Trace / console 证据

- `trace/usr_sbin_uhttpd.txt:690-710`：
  - `0x40b95c -> 0x40ba10`，对应 `cgi_setobject`
  - 说明请求已经根据 `submit_flag` 进入具体配置对象
- `trace/usr_sbin_uhttpd.txt:711-744`：
  - `0x43a5e0` 进入 `config_lan_group`
  - `0x43a820` / `0x43a83c` / `0x43a858` / `0x43a860` 依次出现
  - 第 744 行：`SIGSEGV {si_addr=0x3232325f}`
- `container.console.log`：
  - 出现 `config_lan_group`
  - 随后出现 `[GreenHouseQEMU] SIGSEGV CAUGHT!`

## 结论

- 这是可闭环的真实栈溢出，不是环境噪声。
- source、sink、变量流和 trace/console 现象一致：
  - `body.group_num`
  - `cgi_value("group_num")`
  - `sprintf("lan%s_ipaddr", group_num)` 覆盖 `sp+0x70`
  - `nvram_set` 使用被覆盖的指针并崩溃
- `body` 中其他长字段存在，但当前 crash 地址 `0x3232325f` 与 `group_num` 进入 `lan%s_ipaddr` 的越界字节完全吻合，因此 `group_num` 是本次真实触发字段。
