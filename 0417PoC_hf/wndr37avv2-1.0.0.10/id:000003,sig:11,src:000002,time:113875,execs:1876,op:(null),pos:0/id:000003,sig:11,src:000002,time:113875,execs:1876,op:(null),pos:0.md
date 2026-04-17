# 漏洞分析: wndr37avv2-1.0.0.10 / id:000003,sig:11,src:000002,time:113875,execs:1876,op:(null),pos:0

## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd fcn@0x40f8f8 0x40f978 (lb v1, (s2))`
- Source位置: `/usr/sbin/uhttpd fcn@0x40f8f8 0x40f934 -> sym.cgi_value@0x409060 (读取 body.select_del_mac)`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL pointer dereference / DoS`
- 一句话根因: `apply_qos` 的删除路径先用 `cgi_value("select_del_mac", ...)` 读取表单字段，但返回值未判空，后续在 `0x40f978` 直接按字符串读取首字节，导致缺失字段时稳定空指针崩溃。
- 数据包字段 -> 变量赋值:
  - `body.select_del_mac`(本次请求中缺失) -> `s2 = cgi_value("select_del_mac", ...)` -> `NULL`
  - `body.select_del`(本次请求中缺失) -> `v0 = cgi_value("select_del", ...)` -> `a1` 传给 `del_items("qos_list", a1)`
  - `request.prefix=/apply.cgi?` + `request.handler_name=apply_qos` + `body.submit_flag=qos_del&wzq` -> 命中 QoS 删除处理路径并到达 `fcn@0x40f8f8`
- 执行顺序:
  1. 请求进入 `/apply.cgi?` 的 `apply_qos` 处理逻辑，并进入 QoS 删除分支。
  2. `0x40f934` 调用 `cgi_value("select_del_mac", ...)`，由于请求体缺少该字段，`sym.cgi_value` 在 `0x4090cc` 返回 `NULL`，结果保存在 `s2`。
  3. 代码继续调用 `cgi_value("select_del", ...)` 和 `del_items("qos_list", ...)`，随后在 `0x40f978` 对 `s2` 执行 `lb`，因 `s2==NULL` 触发 `SIGSEGV`。

## Trace映射

- 入口二进制: `/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/rehost_dir/wndr37avv2-1.0.0.10/wndr37avv2_1.0.0.10/debug/fs/usr/sbin/uhttpd`
- Main地址: `0x4041e0`
- 命中的入口trace: `0x40f8f8 -> 0x4090cc -> 0x40f93c -> 0x40f95c -> 0x4092d8 -> 0x409324 -> 0x4093d4 -> 0x40f974 -> SIGSEGV`
- 子进程trace链: `无；当前 crash 证据全部来自 entry_trace.txt`
- 关键pc地址:
  - `0x40f8f8`: 崩溃函数入口
  - `0x4090cc`: `sym.cgi_value` 返回 `NULL`
  - `0x4092d8`: `sym.del_items`
  - `0x409324`: `del_items` 发现参数为空/无效后直接走返回路径
  - `0x40f978`: `lb v1, (s2)`，实际 fault site

## 数据流细节

- 哪些数据包字段控制了哪些变量:
  - `body.select_del_mac` 对应 `cgi_value("select_del_mac", ...)` 的返回值；该值在 `0x40f950` 经 delay slot 写入 `s2`，后续被当作字符串指针使用。
  - `body.select_del` 对应第二次 `cgi_value("select_del", ...)` 的返回值；该值在 `0x40f960` 进入 `a1` 并传给 `del_items("qos_list", a1)`。
  - `request.prefix=/apply.cgi?`、`request.handler_name=apply_qos`、`body.submit_flag=qos_del&wzq` 负责把控制流带到 QoS 删除逻辑；它们不是崩溃指针本身。
- 哪个函数读取了source字段:
  - `fcn@0x40f8f8` 在 `0x40f924/0x40f934` 以常量字符串 `select_del_mac` 调用 `sym.cgi_value@0x409060`。
  - `sym.cgi_value@0x409060` 在 `0x4090a0` 取当前键值对名，循环比较；若未找到，`0x4090cc` 返回 `0`。
- 哪个函数写入 / 拼接 / 格式化了攻击者可控数据:
  - 本次崩溃不是格式化溢出，而是空指针使用。`sym.del_items@0x4092d8` 会把 `select_del` 内容传给 `atoi` 并对配置项做删除，但崩溃前真正危险的指针来自 `select_del_mac` 的 `cgi_value` 返回值。
- 最终如何到达sink:
  - `body.select_del_mac` 缺失
  - `-> cgi_value("select_del_mac", ...)` 返回 `NULL`
  - `-> s2 = NULL` (`0x40f950` delay slot)
  - `-> 继续执行其他删除逻辑，未对 s2 判空`
  - `-> 0x40f978: lb v1, (s2)`
  - `-> si_addr=NULL, SIGSEGV`

## 误报检查

- 为什么这是一个真实漏洞，或者为什么它更像误报:
  - 这是一个真实漏洞。崩溃地址、空地址访问、以及反汇编都一致表明 `uhttpd` 在处理可远程提交的 CGI 表单时对缺失字段 `select_del_mac` 进行空指针解引用。触发条件不依赖未初始化内存、竞争条件或仿真器伪迹。
- 当前缺失的证据:
  - 没有直接看到更上层 dispatcher 的完整反编译命名，因此 QoS 删除分支是根据 `VulPacket.json` 的 `handler_name=apply_qos`、`submit_flag=qos_del&wzq` 与当前 helper 行为联合推断的。
- 对当前现象的替代解释:
  - 最合理替代解释是 POST 解析器未正确生成 `select_del_mac` 项而非字段真的缺失；但这两种情况都会让 `cgi_value("select_del_mac")` 返回 `NULL`，并且都指向同一个真实缺陷: 调用者在使用返回值前没有判空。

## 证据

- 关键trace行:
  - `trace/entry_trace.txt`: `0x40f8f8 -> 0x4090cc -> 0x40f93c -> 0x40f95c -> 0x4092d8 -> 0x409324 -> 0x4093d4 -> 0x40f974 -> --- SIGSEGV {si_addr=NULL} ---`
- 关键容器日志行:
  - `container.console.log`: `[GreenHouseQEMU] SIGSEGV CAUGHT!`
  - `container.console.log`: `[GreenHouseQEMU] SIG 11`
- 关键反编译证据:
  - `0x40f92c`: 形成字符串常量 `select_del_mac`
  - `0x40f934`: 调用 `sym.cgi_value`
  - `0x4090cc`: `sym.cgi_value` 未找到字段时返回 `0`
  - `0x40f950`: `move s2, v0`，把第一次 `cgi_value` 返回值保存为后续字符串指针
  - `0x40f958`: 第二次 `cgi_value` 使用键名 `select_del`
  - `0x40f968`: `jalr t9` 调用 `sym.del_items("qos_list", v0)`
  - `0x40f978`: `lb v1, (s2)`，对空指针直接解引用
