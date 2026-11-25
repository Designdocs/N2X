# REALITY 节点域名访问本机 HTTPS 网站

Xray 内核的 VLESS + TCP（RAW）+ REALITY 节点监听 443 时，N2X 会自动读取 X-Board 的节点域名，检查配套的本机 HTTPS 网站。用户的节点地址、REALITY SNI、密钥和订阅沿用现有配置。

网站须使用覆盖节点域名的有效证书。N2X 从配套网站的 `N2X_ARTX_DECOY_HTTPS_LISTEN` 读取回环监听地址，默认是 `127.0.0.1:50443`。旧面板未下发节点域名时，N2X 尝试使用该节点已有的 DDNS 域名或本地证书域名。

网站在后台通过 TLS 证书和 HTTPS 检查后，浏览器访问节点域名会进入该网站。网站缺失、证书校验失败或返回 5xx 时，N2X 使用原有 REALITY 行为，每 10 秒重新检查。已有代理连接持续使用原连接，网站恢复后自动接收新的网站连接。支持 PROXY protocol v2 的网站可读取客户端 IP；N2X 的代理在线统计使用客户端原始地址。

## 自定义网站

网站使用其他端口时，可在对应节点的 `Options` 中指定该 HTTPS 端口。以下示例使用节点域名和 `127.0.0.1:8443`。

```json
{
  "RealityWebsite": {
    "Port": 8443
  }
}
```

`ServerName` 可覆盖网站域名。`ProxyProtocol: true` 用于要求 PROXY protocol v2 的后端。`Disabled: true` 可关闭网站分流。
