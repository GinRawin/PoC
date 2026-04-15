## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd 0x405590 0x4055d4`
- Source位置: `/usr/sbin/uhttpd 0x408304 0x408328`、`/usr/sbin/uhttpd 0x40b46c 0x40b4bc`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `NULL指针解引用 / 状态失配`
- 一句话根因: `apply.cgi` 这条路径在返回阶段会固定调用公共刷新回调 `0x405590`。本次崩溃不是单一条件导致，而是两个条件共同作用: 一方面 `handle_request` 先把全局 `refresh_url` 清零，而 `submit_flag=ﾌﾇ` 触发的 `cgi_setobject` 路径没有把它恢复；另一方面传给 `0x405590` 的备用参数本来应当从 URL 中 `?` 后面的子串构造出来，但本次请求是 `/apply.cgi`，URL 中没有 `?`，因此这条“备用字符串”构造链没有建立起来，最终 `0x405590` 在 `0x4055d4` 执行 `strstr(NULL, "BRS_")` 触发崩溃。`

## 原始请求还原

- 原始请求方法: `POST`
- 原始 URL: `/apply.cgi`
- 请求体关键字段: `submit_flag=ﾌﾇ`
- `submit_flag=ﾌﾇ` 是请求体字段，不是 URL 参数

## 执行顺序

1. `uhttpd` 接收 `POST /apply.cgi`
2. `handle_request` 在 `0x40832c/0x408334` 清零 `refresh_url`
3. `handle_request` 在 `0x408338/0x40833c` 清零 `refresh_time`
4. `handle_request` 继续沿 `apply.cgi` 对应的处理表进入 `0x405640 -> 0x405804 -> 0x40b46c`
5. `cgi_setobject` 在 `0x40b4bc` 读取 `submit_flag=ﾌﾇ`
6. `cgi_setobject` 保留了后续刷新分发状态，并在 `0x40b6b8` 一类位置继续写 `refresh_time`
7. 但本次 trace 没有出现任何 `refresh_url` 的恢复写回
8. `handle_request` 在尾部执行 `0x408b40 -> 0x408b4c -> 0x405590`
9. `0x405590` 先读取全局 `refresh_url`，发现为空后再使用传入的第一个参数作为 fallback
10. 本次崩溃中这个 fallback 同样为空，最终在 `0x4055d4` 调用 `strstr(NULL, "BRS_")`
11. trace 紧接着结束于 `SIGSEGV si_addr=NULL`

## 关键数据流

- 第一条条件: `refresh_url` 被清空后未恢复
  - `handle_request @ 0x40832c/0x408334` 明确把 `refresh_url` 写成 `0`
  - 本次崩溃 trace 没有命中任何后续 `refresh_url` 恢复写点
- 第二条条件: 传给 `0x405590` 的 fallback 参数也为空
  - `0x408b4c` 把 `s1` 作为第一个参数传入 `0x405590`
  - `0x405590` 的逻辑是: 若 `refresh_url` 为空，则退回使用这个第一个参数
  - 这个备用参数不是凭空来的，它来自请求行解析时保存在 `sp+0x20` 的 URL 相关字符串
  - 本次样本里，这条 URL 备用字符串构造链没有得到有效结果，因此 `strstr` 的第一个参数仍为空
- `submit_flag=ﾌﾇ` 的作用
  - 它不是直接把空指针写进 `0x405590`
  - 它的作用是让请求进入 `cgi_setobject` 这条仍会执行“刷新回调”的路径
  - 但这条路径只保留了刷新分发状态，没有补回 `refresh_url`

## 备用字符串是怎么取出来的

- 第一步: 从请求行里拆出 URL
  - `handle_request` 起始阶段会连续调用 `strsep`
  - `0x4076dc` 把请求行第一段和后续内容切开
  - `0x407714` 继续切出第二段
  - `0x40774c` 之后，`sp+0x20` 中保存的就是请求行里的 URL 指针
  - 对本次请求来说，这里保存的是 `/apply.cgi`
- 第二步: 去掉开头的 `/`
  - `0x4082c4: lw v0, 0x20(sp)`
  - `0x4082c8: addiu s1, v0, 1`
  - 因而 `s1` 变成 `apply.cgi`
- 第三步: 试图从 URL 中再取出 `?` 后面的子串，作为备用字符串
  - `0x408304` 调用 `strchr(s1, '?')`
  - 如果找到了 `?`:
    - `0x40831c` 先把 `?` 的地址写回 `sp+0x20`
    - `0x408320` 把指针加一，变成 `?` 后第一个字节
    - `0x408324` 把原来的 `?` 改成 `\0`
    - `0x408328` 再把 `p + 1` 写回 `sp+0x20`
  - 这套逻辑的实际效果是:
    - `s1` 留下 `apply.cgi`
    - `sp+0x20` 被改写成 URL 中 `?` 后面的那段字符串
- 第四步: 返回阶段重新取出这个字符串
  - `0x408b04: lw s1, 0x20(sp)`
  - `0x408b4c: move a0, s1`
  - 所以真正传给 `0x405590` 的 fallback，不是固定常量，而是 `sp+0x20` 当前保存的那段 URL 派生字符串

## 为什么本次请求会把这个备用字符串弄空

- 本次原始 URL 是 `/apply.cgi`
- 崩溃 trace 命中了:
  - `0x408304`
  - `0x408310`
  - 然后直接到 `0x40832c`
- 这说明:
  - 程序确实执行了“在 URL 中找 `?`”这一步
  - 但没有进入 `0x408320` 这条“把 `sp+0x20` 改成 `?` 后子串”的分支
- 换句话说:
  - 这个备用字符串本来依赖 URL 中的 `?`
  - 本次请求 URL 里没有 `?`
  - 因此没有成功构造出 `?` 后面的备用字符串
  - 到 `0x408b04 -> 0x408b4c -> 0x405590` 这一段时，fallback 实际上仍为空

## 为什么说是两个地方共同作用

- 如果只有第一件事成立:
  - `refresh_url` 被清空，但 `0x405590` 还能拿到一个非空 fallback
  - 那么 `0x405590` 仍可能继续执行，不一定崩
- 如果只有第二件事成立:
  - fallback 为空，但全局 `refresh_url` 已经被正常恢复
  - 那么 `0x405590` 会直接使用 `refresh_url`，同样不一定崩
- 本次漏洞之所以闭环，是因为两件事同时发生:
  - `refresh_url` 没恢复
  - fallback 也为空

## 入口二进制与 Trace 映射

- 入口二进制: `/usr/sbin/uhttpd`
- `trace_summary.json` 已匹配到 `trace/usr_sbin_uhttpd.txt`
- 关键 trace 序列:
  - `pc=0x40821c -> 0x40824c -> 0x408264 -> 0x4082c4 -> 0x4082d8 -> 0x4082e4 -> 0x408304`
  - `pc=0x40832c` 命中 `refresh_url` 清零点
  - `pc=0x405640 -> 0x405804 -> 0x40b46c -> 0x40b4bc` 命中 `cgi_setobject`
  - `pc=0x40b6c4 -> 0x405814 -> 0x408a1c` 返回到 `handle_request` 尾部
  - `pc=0x408b40 -> 0x408b4c -> 0x405590`
  - `pc=0x405590` 后立即 `SIGSEGV si_addr=NULL`

## 关键证据

- `0x40832c/0x408334`
  - `handle_request` 清零 `refresh_url`
- `0x40b4bc`
  - `cgi_setobject` 读取 `submit_flag`
- `0x4076dc/0x407714/0x40774c`
  - `strsep` 逐段拆请求行，并把 URL 保存到 `sp+0x20`
- `0x408304`
  - 对 `s1` 执行 `strchr('?', ...)`
- `0x408320/0x408328`
  - 若 URL 中存在 `?`，则把 `sp+0x20` 改写成 `?` 后面的子串
- `0x408b04`
  - 再次从 `sp+0x20` 取出该字符串给 `s1`
- `0x408b4c`
  - 把 `s1` 作为第一个参数传入 `0x405590`
- `0x405590`
  - 先读取 `refresh_url`
  - 若其为空，则退回使用传入参数
- `0x4055d4`
  - 调用 `strstr`
- `trace/usr_sbin_uhttpd.txt`
  - 在 `pc=0x405590` 后直接结束于 `SIGSEGV si_addr=NULL`

## 结论

- 这是一个可以闭环解释的 `NULL` 指针解引用漏洞。
- 根因不是单独的 `refresh_url == NULL`，也不是单独的 URL fallback 为空，而是二者共同成立:
  - `refresh_url` 被 `handle_request` 清零后没有恢复
  - `0x405590` 的 fallback 参数本来应由 URL 中 `?` 后面的字符串提供，但本次 `/apply.cgi` 因为没有 `?`，这条备用字符串构造链没有建立起来，最终也为空
- `submit_flag=ﾌﾇ` 的作用是把请求带入仍会执行刷新回调的 `cgi_setobject` 路径，从而把这两个条件在同一次请求里拼接起来，最终触发 `strstr(NULL, "BRS_")` 崩溃。

## 命中benchmark:否

## 0-day:是
