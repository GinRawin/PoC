## 摘要

- 判定: `确认漏洞`
- Sink位置: `/usr/sbin/uhttpd 0x446658 0x4466dc`
- Source位置: `/usr/sbin/uhttpd 0x405640 0x4056a4`
- 漏洞二进制: `/usr/sbin/uhttpd`
- 漏洞类型: `参数校验缺失`
- 一句话根因: `uhttpd`  access-control 处理函数仍然对缺失的 `hidden_change_num` 结果直接执行 `atoi(NULL)`。
- 数据包字段 -> 变量赋值:
  - `request.method=POST` + `request.prefix=/` + `request.handler_name=apply.cgi?upgrade_check.cgi` -> 原始请求 URL 为 `/apply.cgi?upgrade_check.cgi`
  - `body.submit_flag=acc_control_allow` -> `fcn.00405640` 构造出的 CGI 表 `sp+0x18` -> `cgi_setobject @ 0x40b46c` 的 `cgi_value("submit_flag") @ 0x40b4bc` -> 选中 access-control 分支
  - 缺失后的 `hidden_change_num` -> `cgi_value("hidden_change_num") @ 0x4466c8` 返回 `NULL` -> `atoi` 的 `a0=NULL` -> `atoi @ 0x4466dc`

## 命中benchmark:是

## 0-day:是
