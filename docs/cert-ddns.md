# 自动申请证书说明

N2X 支持多种自动申请证书配置。申请到的证书将会放在配置文件`config.json`指定的目录下。

以下是自动申请证书的相关配置文件说明。

```json
      "CertConfig": {
        // 证书申请模式，none、http、dns、self
        "CertMode": "none",
        "RejectUnknownSni": false,
        // 证书域名
        "CertDomain": "test.com",
        // 证书文件目录
        "CertFile": "/etc/N2X/fullchain.cer",
        // 密钥文件目录
        "KeyFile": "/etc/N2X/cert.key",
        // 申请证书时使用的用户邮箱
        "Email": "n2x@github.com",
        // DNS解析提供者 详见https://go-acme.github.io/lego/dns/的CLI flag name列
        "Provider": "cloudflare",

        // DNS解析提供者的环境变量，详见https://go-acme.github.io/lego/dns/，以cloudflare为例
        "DNSEnv": {
          "CF_DNS_API_TOKEN": "填入仅授权所需域名的API Token"
        }
      }
```

Cloudflare 的 DNS 模式使用 API Token。在[API Tokens 页面](https://dash.cloudflare.com/profile/api-tokens)创建令牌，授予 `Zone / DNS / Edit` 和 `Zone / Zone / Read` 权限，区域资源选择 `Include / Specific zone`，仅包括需要申请证书的域名。这里的区域权限覆盖该 Zone 下的全部 DNS 记录，不能只限制到其中一条子域名记录。参考 [Cloudflare 创建说明](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)和 [lego Cloudflare 配置说明](https://go-acme.github.io/lego/dns/cloudflare/)。

将 `CertMode` 设置为 `dns`，在 `DNSEnv.CF_DNS_API_TOKEN` 中填写 Token。也可以在 `/etc/N2X/.env` 中设置 `CF_DNS_API_TOKEN=你的Token`，并将配置值写为 `"CF_DNS_API_TOKEN": "${CF_DNS_API_TOKEN}"`。外层的 `Email` 是 ACME 证书账户邮箱，Token 认证不需要在 `DNSEnv` 中填写 Cloudflare 邮箱。

从全局 Key 迁移时，替换整个 Cloudflare `DNSEnv`，删除旧的 `CF_API_KEY`、`CLOUDFLARE_API_KEY`、`CF_API_EMAIL`、`CLOUDFLARE_EMAIL`（包括 `.env`、systemd 或容器环境中的旧值），避免旧凭据优先被使用。旧配置仍可读取，但新配置和示例统一使用 `CF_DNS_API_TOKEN`。更换 Token 后，已有证书可能直接被复用；仅重启成功不能证明 DNS 写入权限有效。

| 参数                 | 选项                         | 说明                                                                                                                                                                                              |
| ------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CertMode`         | `none`,`http`,`dns`,`self` | <p>获取证书的方式。</p><p><code>none</code>：强制关闭tls设置。</p><p><code>http</code>：通过http申请，需要80端口。</p><p><code>dns</code>：使用dns模式申请，需要制定相关dns服务商配置。</p><p><code>self</code>:指定文件路径手动提供，若路径无文件则使用自签名证书。</p> |
| `RejectUnknownSni` | `true`, `false`            | Xray内核专用，服务端接收到的 SNI 与证书域名不匹配即拒绝 TLS 握手，默认为`false`。                                                                                                                                             |
| `CertDomain`       | 无                          | 申请证书域名                                                                                                                                                                                          |
| `CertFile`         | 无                          | 手动指定的证书路径                                                                                                                                                                                       |
| `KeyFile`          | 无                          | 手动指定的私钥路径                                                                                                                                                                                       |
| `Provider`         | 无                          | dns提供商，所有支持的dns提供商请在此获取：[https://go-acme.github.io/lego/dns/](https://go-acme.github.io/lego/dns/)                                                                                              |
| `DNSEnv`           | 无                          | 采用DNS申请证书需要的环境变量，请参考上文链接内，自己的dns提供商所需要的参数，填写于此。请注意一行一个，填写时需符合json文件格式。                                                                                                                          |

## DDNS：自动更新公网 IP

DDNS 与证书申请独立，节点中在 `CertConfig` 后添加同级的 `DDNSConfig`。默认 `Enabled: false`，省略整个配置也保持关闭，不进行公网 IP 查询或 DNS 修改。引导在完成证书配置后询问是否开启 DDNS，回车为关闭；不添加证书时不显示 DDNS 提示。

Cloudflare 示例（Token 可使用证书申请时同样的限定域名权限）：

```json
"DDNSConfig": {
  "Enabled": true,
  "Provider": "cloudflare",
  "Domain": "node.example.com",
  "ZoneName": "example.com",
  "RecordType": "A",
  "Interval": 300,
  "TTL": 600,
  "IPURL": "",
  "DNSEnv": {
    "CF_DNS_API_TOKEN": "${CF_DNS_API_TOKEN}"
  }
}
```

阿里云国际平台将服务商及凭据改为：

```json
"Provider": "alidns",
"DNSEnv": {
  "ALICLOUD_ACCESS_KEY": "${ALICLOUD_ACCESS_KEY}",
  "ALICLOUD_SECRET_KEY": "${ALICLOUD_SECRET_KEY}"
}
```

在 `/etc/N2X/.env` 中填写国际账号的 RAM AccessKey，可选 `ALICLOUD_SECURITY_TOKEN` 用于临时凭据。使用 HTTPS 公共接口 `alidns.aliyuncs.com`；国际账号与其他账号使用同一 AliDNS API。RAM 用户授予目标域名的 `alidns:DescribeDomainRecords`、`alidns:AddDomainRecord`、`alidns:UpdateDomainRecord` 即可，无需删除记录权限。接口说明见 [Alibaba Cloud DNS API](https://www.alibabacloud.com/help/en/dns/quick-start-1)。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `Enabled` | `false` | 显式开启后才启动 DDNS |
| `Provider` | 沿用本地证书配置 | `cloudflare` 或 `alidns` |
| `Domain` | `CertConfig.CertDomain` | 需要更新的具体主机名；泛域名证书须单独填写，不能用 `*.example.com` |
| `ZoneName` | 按公共后缀推断注册域名 | 如 `example.co.uk`；实际托管子区域时需手动指定 |
| `RecordType` | `A` | `A` 更新 IPv4，`AAAA` 更新 IPv6 |
| `Interval` | `300` | 检查间隔，单位秒，允许 30–86400 |
| `TTL` | `600` | 仅创建记录时使用，更新保留原 TTL；Cloudflare 可填 1 表示自动，阿里云至少 600 |
| `IPURL` | `https://api.ipify.org` 或 `https://api6.ipify.org` | 返回纯文本公网 IP 的 HTTPS 地址，查询按记录类型使用 IPv4/IPv6，绕过代理 |
| `DNSEnv` | 同一服务商的 `CertConfig.DNSEnv` | 可单独填写 DDNS 凭据；不会混用不同服务商凭据 |

首次同步在节点启动与证书申请之前执行，之后持续定时同步，即使面板或证书暂时失败也会继续。相同 DDNS 配置去重，配置重载或退出时停止旧任务。IP 未变不写入；记录缺失会创建；更新保留 Cloudflare 代理开关及阿里云线路。Cloudflare 新建记录默认不代理。匹配到多条同名同类型记录或阿里云记录被停用时拒绝修改，需要先在 DNS 控制台处理。关闭功能不会删除已有记录。

## 阿里云国际账号申请 SSL 证书

域名的权威 DNS 需要托管在阿里云云解析。项目通过 Let's Encrypt 签发证书，AliDNS 用于创建和清理 DNS 验证 TXT 记录，无需额外授予阿里云证书管理服务权限。

节点中的证书配置示例：

```json
"CertConfig": {
  "CertMode": "dns",
  "RejectUnknownSni": false,
  "CertDomain": "node.example.com",
  "CertFile": "/etc/N2X/fullchain-{domain}.cer",
  "KeyFile": "/etc/N2X/cert-{domain}.key",
  "Email": "ops@example.com",
  "Provider": "alidns",
  "DNSEnv": {
    "ALICLOUD_ACCESS_KEY": "${ALICLOUD_ACCESS_KEY}",
    "ALICLOUD_SECRET_KEY": "${ALICLOUD_SECRET_KEY}"
  }
}
```

在 `/etc/N2X/.env` 设置对应的 RAM AccessKey ID 和 Secret。`Email` 是证书账户邮箱。普通 RAM AccessKey 不需要 `ALICLOUD_SECURITY_TOKEN`，STS 临时凭据才需要该字段。DDNS 也使用 `alidns` 且 `DNSEnv` 留空时，可以复用以上凭据。

## 同时用于 SSL 与 DDNS 的指定域名 RAM 策略

在 RAM 创建自定义权限策略，通过 JSON 编辑模式填入以下内容，并替换 `ACCOUNT_UID` 为域名所属主账号 UID，替换 `example.com` 为云解析中实际托管的域名。多个域名在第二条的 `Resource` 数组中逐个列出。

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["alidns:DescribeDomains"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "alidns:DescribeDomainRecords",
        "alidns:AddDomainRecord",
        "alidns:UpdateDomainRecord",
        "alidns:DeleteDomainRecord"
      ],
      "Resource": [
        "acs:alidns:*:ACCOUNT_UID:domain/example.com"
      ]
    }
  ]
}
```

第一条只允许读取域名列表，这是当前 lego 证书插件查找托管区域需要的操作，阿里云要求其资源范围为 `*`。记录查询、新建、修改和删除仍限定到第二条列出的域名下。证书验证会创建和删除 TXT 记录；DDNS 会查询、新建或更新 A/AAAA 记录。

将策略授权给创建 AccessKey 的 RAM 用户，选择账号级授权范围，由策略中的 `Resource` 限定域名。用户及所属用户组若仍有 `AliyunDNSFullAccess` 等广泛授权，需要在完成替换验证后移除，否则多条 Allow 策略会叠加。参考[官方指定域名策略](https://www.alibabacloud.com/help/en/dns/alibaba-cloud-dns-custom-permission-policy-reference-dns)与 [DescribeDomains 授权规则](https://help.aliyun.com/en/dns/api-alidns-2015-01-09-describedomains)。
