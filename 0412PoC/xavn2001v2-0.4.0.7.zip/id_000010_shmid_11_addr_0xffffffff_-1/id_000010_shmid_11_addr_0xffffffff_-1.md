## 摘要

- 判定: 确认漏洞
- 与代表样本关系: 同属 `wlan_adv` 崩溃族，但当前 case 已独立闭环出真实 `source -> variable -> sink`
- 代表样本: `id:000008,shmid:11,addr:0xffffffff,-1`
- Sink位置: `0x437844/0x43784c`，`t9 = GOT[-32212] = strcmp`，实参为 `a0 = s2`、`a1 = 0x4516f0 ("1")`
- Source位置: `0x437790/0x43779c`，`t9 = GOT[-31476] = cgi_value`，实参为 `a0 = 0x45e048 ("wla_enable_router")`、`a1 = s3`、`a2 = s4`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: 空指针解引用
- 一句话根因: `config_wladv` 假定 `wla_enable_router` 一定存在；当请求只提供 `wl_enable_router` 且其值不为 `"1"` 时，代码会把缺失字段 `wla_enable_router` 的 `NULL` 返回值直接传给 `strcmp`，最终在 `0x437840` 附近触发 `SIGSEGV si_addr=NULL`。
- 数据包字段 -> 变量赋值:
  - `body.submit_flag = wlan_adv` -> `cgi_setobject(0x40b95c)` 通过 `cgi_value("submit_flag")` 取到分派键 -> `cgi_func` 查 `0x471890` 处分发表，命中项 `0x44e20c ("wlan_adv") -> 0x437540`，进入 `config_wladv`
  - `body.wl_enable_router = 2222...` -> `0x437770/0x43777c` 调 `cgi_value("wl_enable_router", s3, s4)` -> 返回的非空 value 指针在 `0x4377a0` 被放入 `s1`
  - `body.wla_enable_router` 缺失 -> `0x437790/0x43779c` 调 `cgi_value("wla_enable_router", s3, s4)` -> 返回 `v0 = NULL`，并在 `0x4377b8` 的 delay slot 赋给 `s2`
  - `s1` 指向的 `wl_enable_router` 值不是 `"1"` -> `0x4377a4..0x4377bc` 的第一次 `strcmp(s1, "1")` 非零，分支落到 `0x437840`
  - `s2 = NULL` -> `0x437844..0x437850` 的第二次 `strcmp(s2, "1")` 直接解引用空指针并崩溃
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi`
  2. `submit_flag=wlan_adv` 令 `cgi_setobject/cgi_func` 将请求分派到 `config_wladv(0x437540)`
  3. `config_wladv` 打印 `config_wladv Enter`、`STEP 1`、`STEP 2`
  4. 读取 `wl_enable_router` 后，继续读取缺失的 `wla_enable_router`
  5. `cgi_value("wla_enable_router")` 返回 `NULL`
  6. `strcmp(NULL, "1")` 在 `0x437840` 附近触发 `SIGSEGV si_addr=NULL`

## 与代表样本对比

- 相同点:
  - 二者都落在 `/usr/sbin/uhttpd`
  - 二者都由 `submit_flag=wlan_adv` 分派进入 `config_wladv`
  - console 都打印了 `config_wladv Enter`、`STEP 1`、`STEP 2`
  - trace 都在 `0x4375xx` 到 `0x4378xx` 附近结束并报 `SIGSEGV`
- 当前 case 比旧结论多出的关键证据:
  - 已核实 `cgi_value` 的真实返回约定: 命中返回 value 指针，未命中返回 `NULL`
  - 已从 `0x471890` 的分发表中解出 `wlan_adv -> 0x437540`
  - 已核实 `0x437790/0x43779c` 读取的是 `wla_enable_router`
  - 已核实 `0x437844/0x43784c` 实际调用的是 `strcmp(s2, "1")`
- 因此，这次不再是“`wlan_adv` 路径里某处未知崩溃”，而是可精确说明的 `NULL` 指针解引用。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi`
- handler: `apply.cgi`
- 以上 URL/handler 来自 `VulPacket.json.packet_1.request.prefix` 与 `VulPacket.json.packet_1.request.handler_name`
- `body.show_traffic=upgrade_check_free.cgi` 只是 body 参数，不是原始请求 URL
- 与本次崩溃直接相关的 body 字段:
  - 存在: `submit_flag=wlan_adv`
  - 存在: `wl_enable_router=2222...`
  - 缺失: `wla_enable_router`

## Trace映射与关键证据

- `trace_summary.json` 将入口 `main=0x4047d4` 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 行:
  - `699: pc=0x437540`，进入 `config_wladv`
  - `734: pc=0x4375e8`，进入 `STEP 1/STEP 2` 之后的主体逻辑
  - `752: pc=0x437784`，开始第二次 `cgi_value` 取参
  - `753: pc=0x40b514`，`cgi_value("wla_enable_router")` 返回到调用者
  - `754: pc=0x4377a4`，第一次 `strcmp(s1, "1")`
  - `755: pc=0x4377bc`，第一次比较结束并分支
  - `756: pc=0x437840`，第二次 `strcmp(s2, "1")` 的调用块
  - `757: --- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- `container.console.log`:
  - 第 24 行: `=================config_wladv Enter===========`
  - 第 26 行: `=================STEP 1===========`
  - 第 27 行: `=================STEP 2===========`
  - 第 28-29 行: `SIGSEGV CAUGHT!` / `SIG 11`
- console 与 trace 一致表明：崩溃发生在 `config_wladv` 的 `STEP 2` 之后，而不是其他子进程或其他二进制。

## Source / Variable / Sink 闭环

- handler 分派:
  - `cgi_setobject(0x40b95c)` 在 `0x40b9a8` 以字符串常量 `0x45dd34 ("submit_flag")` 调 `cgi_value`
  - `cgi_func` 使用 `0x471890` 开始的 12 字节表项查 handler；其中 `0x471a88` 的字符串指针为 `0x44e20c ("wlan_adv")`，函数指针为 `0x437540`
- `cgi_value` 语义:
  - `0x40b4a4` 内部把 `a0` 当作 key、`a1` 当作 `(key,value)` 数组起始地址、`a2` 当作元素个数
  - `0x40b4e0` 取当前项的 key，`0x40b4e8` 调 `strcmp`
  - 比较成功时 `0x40b4f8` 返回当前项 `value` 指针；遍历失败时走到 `0x40b514` 返回 `NULL`
- 触发 source:
  - `0x437790: addiu a0,a0,-8120`，得到常量 `0x45e048 ("wla_enable_router")`
  - `0x43778c: move a1,s3`
  - `0x437794: move a2,s4`
  - `0x43779c: jalr t9`，其中 `t9 = GOT[-31476] = cgi_value`
  - 当前数据包没有这个 body key，因此 `cgi_value` 返回 `v0 = NULL`
- variable 赋值:
  - `0x4377b4: jalr t9` 发起第一次 `strcmp(s1, "1")`
  - `0x4377b8` 的 delay slot 执行 `move s2, v0`
  - 这里的 `v0` 正是前一条 `cgi_value("wla_enable_router")` 的返回值，因此 `s2 = NULL`
- 控制条件:
  - `0x437770/0x43777c` 用 `0x45e034 ("wl_enable_router")` 调 `cgi_value`
  - 返回值在 `0x4377a0` 放入 `s1`
  - `0x4377a4..0x4377bc` 调 `strcmp(s1, 0x4516f0)`；文件偏移 `0x516f0` 的字节是 `31 00`，即常量字符串 `"1"`
  - 数据包中的 `wl_enable_router` 是长串 `2222...`，不是 `"1"`，所以分支落到 `0x437840`
- sink 调用点:
  - `0x437840: lui s0,0x45`
  - `0x437844: lw t9,-32212(gp)`，GOT 槽内容为 `0x0044b5b0 = strcmp`
  - `0x437848: move a0,s2`
  - `0x43784c: jalr t9`
  - `0x437850: addiu a1,s0,0x16f0`，即第二个实参 `"1"`
  - 因为 `s2 = NULL`，`strcmp(NULL, "1")` 触发空指针解引用；这与 trace 第 756-757 行完全一致

## 为什么这次可以确认漏洞

- 已经具备可解释的 source:
  - `cgi_value("wla_enable_router")` 是明确的字段读取点
- 已经具备可解释的 sink:
  - `strcmp(s2, "1")` 是明确的崩溃调用点
- 已经具备可解释的数据流:
  - 缺失字段 `wla_enable_router` -> `cgi_value` 返回 `NULL` -> `s2 = NULL` -> `strcmp(s2, "1")`
- 已经具备与 trace / console / 反汇编一致的证据闭环:
  - handler 分派、字段名常量、GOT 解析、trace 地址、最终 `SIGSEGV si_addr=NULL` 全部互相一致
- 因此本 case 应从先前的 `证据不足` 更新为 `确认漏洞`。
