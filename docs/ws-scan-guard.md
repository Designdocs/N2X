# 节点扫描防护

在落地机的 N2X 管理菜单选择「25. 节点扫描防护」，可开启、关闭或查看拦截日志。默认关闭，也可在 `/etc/N2X/config.json` 顶层设置：

```json
{
  "WSScanGuard": {
    "Enabled": false,
    "LogMaxMB": 10
  }
}
```

开启后，节点先按自身配置匹配代理路径。对于落到错误入口的请求，访问 Git 元数据、环境配置文件、WordPress 后台、phpMyAdmin 或 Actuator 敏感端点，以及向错误路径发起 WebSocket 握手，均直接返回 HTTP 404。普通网页请求继续使用该节点原有的回落行为。

适用于 Xray 的 WS、XHTTP 和 HTTPUpgrade 错误路径，以及 sing-box 的 WS、HTTP、HTTPUpgrade、轻量 gRPC 错误路径和 Naive 的本机网页请求。

日志记录 UTC 时间、节点、请求路径和命中规则。日志目录默认为 `/var/lib/N2X/ws-scan`，可用 `N2X_WS_SCAN_STATE_DIR` 修改。当前文件 `intercepts.jsonl` 与上一份 `intercepts.jsonl.1` 合计默认最多 10 MiB。
