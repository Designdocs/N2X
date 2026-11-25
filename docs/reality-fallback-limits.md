# REALITY 回落限速

在使用 Xray 和 REALITY 的节点上，可以对未通过 REALITY 鉴权、被转发至目标站点的连接限速。每条回落连接独立计速，上传和下载可以分别开启。默认两个方向都关闭。已认证用户继续使用原有的用户限速策略。

在 `Nodes` 中对应的节点加入所需方向的字段。使用分组配置时，字段放在该节点的 `Options` 内。下面的配置片段将回落下载的持续速率设为 256 KiB/s。

```json
{
  "limitFallbackDownload": {
    "afterBytes": 65536,
    "bytesPerSec": 262144,
    "burstBytesPerSec": 524288
  }
}
```

- `limitFallbackUpload` 控制客户端发往目标站点的数据，`limitFallbackDownload` 控制目标站点发回客户端的数据。两个方向的字段格式相同。
- `afterBytes` 是开始限速前可传输的字节数，默认 0。
- `bytesPerSec` 是持续速率，单位为字节/秒。设为 0 或删除对应方向的配置即可关闭该方向限速。
- `burstBytesPerSec` 控制桶最多可积攒的字节数。桶开始时是满的，容量至少为一秒的持续速率。示例中，前 64 KiB 通过后还可消耗最多 512 KiB 的突发额度。
- sing-box 节点配置任一方向都会报错。切换到 sing-box 前，请删除这两个字段。

并发连接的流量会叠加，有流量配额的节点可在 VPS 厂商后台设置出站流量告警。批量配置时按各节点目标站的资源大小分别选取参数。[REALITY 官方说明](https://xtls.github.io/config/transports/reality.html#realityobject)
