## 摘要

- 判定: 确认漏洞
- 与代表样本关系: 同属 PLC QoS 端口配置崩溃族，但当前样本已能独立闭合到真实 sink
- 代表样本: `id:000051,shmid:11,addr:0xffffffff,-1`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: NULL 指针解引用 / 拒绝服务
- Source位置:
  - 控制分发: `0x471bfc/0x471c00` 的分发表项把 `submit_flag=plc_qos_port_add` 映射到 handler `0x4312b8`
  - 字段读取: `0x4312f4` `cgi_value("qos_port_priority", req, ctx)`，`0x431318` `cgi_value("plc_qos_port", req, ctx)`
- Sink位置: `0x4308a0`，`jalr t9` 调用 `strcpy(dst=s2, src=v0)`；MIPS delay slot `0x4308a4` 把 `a1=v0` 装入，trace 显示的 `0x430894` 只是该危险调用前的准备指令
- 一句话根因: `plc_qos_port_add` 路径在重建 `/tmp/rules.txt` 时，未检查 `get_string_segment(..., 1, ...)` 是否成功；当 `plc_qos_port1` 只有占位值 `Unknown`、缺少第二个 token 时，返回 `NULL` 并被直接传给 `strcpy` 导致崩溃
- 数据包字段 -> 变量赋值:
  - `request.method=POST`, `request.handler_name=apply.cgi?pls_wait.html` -> 原始请求 URL 为 `/apply.cgi?pls_wait.html`
  - `body.submit_flag=plc_qos_port_add` -> 分发表项 `0x471bfc/0x471c00` -> handler `0x4312b8`
  - `body.qos_port_priority` -> `0x4312f4` 返回值保存到 `s1`
  - `body.plc_qos_port` -> `0x431318` 返回值保留在 `v0`
  - `s1` 与 `v0` 在 `0x43132c..0x431340` 通过 `sprintf("%s %s", ...)` 拼到栈缓冲区 `sp+0x18`
  - `sp+0x18` 在 `0x431350/0x431354` 作为 `add_items("plc_qos_port", buf)` 的第二实参传入；其内部具体写入索引未知
  - 随后 `0x431360/0x431364` 立即调用 `plc_rules_file_update()`
  - `0x4307e4..0x43080c` 生成并读取 `nvram_get("plc_qos_port1")`
  - 当读取结果为空时，`0x430820..0x430824` 以常量回退值替代；console 佐证该值在本次运行中表现为 `plc_qos_port1=Unknown`
  - 第二次分段提取 `0x43088c` 返回 `NULL`，该 `NULL` 在 `0x4308a4` 进入 `a1`，并在 `0x4308a0` 被 `strcpy` 解引用
- 执行顺序:
  1. `uhttpd` 收到 `POST /apply.cgi?pls_wait.html`
  2. `submit_flag=plc_qos_port_add` 通过分发表进入 `0x4312b8`
  3. handler 读取 `qos_port_priority` 与 `plc_qos_port`
  4. handler 组装字符串并调用 `add_items("plc_qos_port", buf)`
  5. handler 立即调用 `plc_rules_file_update()`
  6. `fcn.00430780` 处理 `plc_qos_port%d`，本次读取到 `plc_qos_port1=Unknown`
  7. 第二次 `get_string_segment(..., 1, ...)` 沿 `0x4306f8 -> 0x430760` 返回 `NULL`
  8. `0x4308a0` 的 `strcpy(dst, NULL)` 触发 `SIGSEGV`

## 与代表样本对比

- 相同点:
  - 二者都落在 `/usr/sbin/uhttpd` 的 PLC QoS 配置路径。
  - 二者最终都在 `0x430894` 邻近区域崩溃，并且 `si_addr=NULL`。
- 不同点:
  - 当前样本可独立确认 `submit_flag=plc_qos_port_add -> 0x4312b8` 的真实分发关系。
  - 当前样本可独立确认真实危险 sink 不是抽象的“0x430894 一带”，而是 `0x4308a0` 的 `strcpy(dst=s2, src=v0)`。
  - 当前样本还可解释 `NULL` 的来源: `plc_qos_port1` 缺少第二段，导致第二次 `get_string_segment` 返回 `NULL`。
- 结论:
  - 代表样本第一轮停在 `证据不足`，但当前样本通过 callsite 核验已经能独立升级为 `确认漏洞`。

## 原始请求

- 方法: `POST`
- URL: `/apply.cgi?pls_wait.html`
- handler: `apply.cgi?pls_wait.html`
- header: `HOST=192.168.0.50`, `Content-Type=xml/text`, `Cookie=uid=xhyxhy`
- 关键 body 字段:
  - `submit_flag=plc_qos_port_add`
  - `qos_port_priority=2222...`
  - `plc_qos_port=1`
  - `plc_qos_mac_addr=1`
  - `/tmp/rules.txt=22222222`
- 说明:
  - `show_traffic=debuginfo.htm` 和 `body` 内出现的 `/tmp/rules.txt` 都只是参数，不是原始请求 URL。

## Trace映射与关键证据

- `trace_summary.json` 将入口 `main=0x4047d4` 精确匹配到 `trace/usr_sbin_uhttpd.txt`
- trace 尾部:
  - `pc=0x430870`
  - `pc=0x430884`
  - `pc=0x43068c`
  - `pc=0x4306f8`
  - `pc=0x430760`
  - `pc=0x430894`
  - `--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---`
- `container.console.log`:
  - `plc_qos_port1=Unknown`
  - `plc_qos_mac1=Unknown`
  - `[GreenHouseQEMU] SIGSEGV CAUGHT!`
- 解释:
  - `0x43068c -> 0x4306f8 -> 0x430760` 对应 `get_string_segment` 的失败返回路径。
  - trace 停在 `0x430894`，但 MIPS 真正的危险调用是后面的 `0x4308a0 jalr t9`，其 `a1=v0` 来自 delay slot `0x4308a4`。

## Source分析

- `submit_flag` 分发证据:
  - 数据表 `0x471bf0..0x471c08` 中包含:
    - `0x471bfc = 0x44e424`，对应字符串 `plc_qos_port_add`
    - `0x471c00 = 0x4312b8`，对应 add handler
    - `0x471c08 = 0x44e438`，对应字符串 `plc_qos_port_edit`
    - `0x471c10 = 0x431070`，对应 edit handler
  - 因此本次 `body.submit_flag=plc_qos_port_add` 的真实目标函数是 `0x4312b8`，不是 `plc_qos_port_edit`
- `0x4312b8` 内的字段读取 callsite:
  - `0x4312e0` 先取 `t9=sym.cgi_value`
  - `0x4312e4/0x4312ec` 通过 `lui/addiu` 装入字符串地址 `0x45b41c = "qos_port_priority"`
  - `0x4312f4` `jalr t9`，delay slot `0x4312f8` 把第三实参 `a2=s2` 装入
  - 返回后 `0x431304` 把结果保存到 `s1`
  - `0x43130c` 再次装入 `t9=sym.cgi_value`
  - `0x431314` 装入 `0x45b324 = "plc_qos_port"`
  - `0x431318` `jalr t9`，delay slot `0x43131c` 同样传入 `a2=s2`
- 请求字段如何进入中间变量:
  - `0x43132c` 调用 `sprintf`
  - `0x431334` 装入格式串 `0x4520d0 = "%s %s"`
  - `0x431338` 把 `a2=s1`
  - `0x43133c` 把 `a3=v0`
  - `0x431344` 把目标缓冲区设置为 `s0 = sp+0x18`
  - 因此 handler 明确把 `qos_port_priority` 与 `plc_qos_port` 拼成 `"priority port"` 形式的临时字符串
- 之后的传播:
  - `0x431348` 把 `a0` 设为 `"plc_qos_port"`
  - `0x431350/0x431354` 调用 `add_items("plc_qos_port", sp+0x18)`
  - `0x431360/0x431364` 紧接着调用 `plc_rules_file_update()`

## Sink分析

- `plc_rules_file_update` 的调用链:
  - `0x430904` 为 `sym.plc_rules_file_update`
  - `0x430928` 打开 `/tmp/rules.txt`
  - `0x430948` 先调用 `fcn.00430780(file, "plc_qos_mac", "EthDA")`
  - `0x430960` 再调用 `fcn.00430780(file, "plc_qos_port", "IPDP")`
- `fcn.00430780` 如何走到崩溃:
  - `0x4307e8..0x4307fc` 用格式串 `0x45dfd4 = "%s%d"` 构造键名
  - 对当前分支，传入基名是 `"plc_qos_port"`，因此首次构造出的键是 `plc_qos_port1`
  - `0x430808/0x43080c` 调用 `nvram_get(key)`
  - `0x430820..0x430824` 用回退常量替代空返回值；console 明确印证本次运行得到的是 `plc_qos_port1=Unknown`
  - `0x43084c` 第一次调用 `get_string_segment`，取第 0 段
  - `0x43088c` 第二次调用 `get_string_segment`，取第 1 段
  - 当输入为 `Unknown` 这类单 token 字符串时，第 1 段不存在，`get_string_segment` 在 `0x4306f8 -> 0x430760` 返回 `NULL`
- 真实危险 sink:
  - `0x430894 move a0, s2`
  - `0x43089c lw t9, -sym.imp.strcpy(gp)`
  - `0x4308a0 jalr t9`
  - `0x4308a4 move a1, v0`
  - 因为 `v0 == NULL`，所以这里实际执行的是 `strcpy(s2, NULL)`，这才是导致 `SIGSEGV si_addr=NULL` 的真实 faulting operation

## 数据流闭环

- 已确认的闭环部分:
  - HTTP body 的 `submit_flag=plc_qos_port_add` 真实进入 `0x4312b8`
  - `0x4312b8` 真实读取 `qos_port_priority` 与 `plc_qos_port`
  - 两个字段被真实拼接为栈字符串，并作为 `add_items("plc_qos_port", buf)` 的实参传递
  - 同一路径立即调用 `plc_rules_file_update()`
  - `plc_rules_file_update()` 真实遍历 `plc_qos_port%d`
  - 当前运行中 `plc_qos_port1` 真实表现为 `Unknown`
  - 第二次 `get_string_segment` 真实返回 `NULL`
  - `NULL` 真实进入 `strcpy` 的源参数并触发崩溃
- 仍然不透明但不影响结论的点:
  - `add_items` 内部到底如何分配索引、为何本次最终读到的是 `plc_qos_port1=Unknown`，该内部细节尚未完全展开
  - 该点会影响“配置写入的精细语义”，但不会改变已核验的 crash 事实: 本次请求可把程序带到 `strcpy(dst, NULL)` 的真实 sink
- 因此本样本不是误报，也不是单纯“现象相似”:
  - source 已确认
  - sink 已确认
  - `source -> variable -> sink` 已能解释为 `submit_flag / qos_port_priority / plc_qos_port -> 拼接后的 PLC QoS 项 -> plc_qos_port1 缺少第二段 -> get_string_segment(...,1)=NULL -> strcpy(NULL)`

## 为什么不是误报

- 如果这是误报，至少应出现以下任一情况:
  - 请求没有进入与 `submit_flag=plc_qos_port_add` 对应的真实 handler
  - trace/console 与静态代码路径对不上
  - 崩溃点不是可解释的真实库调用，而只是模糊的“附近地址”
- 当前样本不满足这些误报条件:
  - 分发表、handler、trace、console、sink callsite 彼此一致
  - `si_addr=NULL` 与 `strcpy(dst, NULL)` 完全吻合
  - `plc_qos_port1=Unknown` 与第二次取 segment 失败也完全吻合

## 结论

- 当前 crash 对应的真实漏洞在 `/usr/sbin/uhttpd`
- 这是一个 PLC QoS 端口配置路径上的 NULL 指针解引用漏洞，可导致远程请求触发的进程崩溃
- 最直接的修复点在 `fcn.00430780`:
  - 在 `0x43088c` 之后检查 `get_string_segment(..., 1, ...)` 的返回值
  - 在 `0x4308a0` 的 `strcpy` 前拒绝 `NULL`
  - 同时应校验 `plc_qos_port%d` 项是否至少包含两个由分隔逻辑认可的 token
