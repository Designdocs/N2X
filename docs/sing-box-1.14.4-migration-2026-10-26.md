# 2026-10-26 sing-box v1.14.4 完整迁移

本文记录完整迁移阶段；后续正式模块固定、推送与 v0.17.10 构建情况见 [上线评估](release-readiness-2026-10-26.md)。

本次在前一轮稳定修复回移之后，完成官方 [SagerNet/sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) 的完整本地合并。原定制历史保留，未推送远端、发布安装包或部署节点。

| 项目 | 最终本地源码 | 来源 |
| --- | --- | --- |
| sing-box | `9b671548395f8ce1ed6c169f465daf97ea567b2f` | 合并父提交 `77c9325a6e2b8ea040b1a45047abd54719571329` 与官方 `c005f35300ce76427dc285481ec5695f5b179cd2` |
| Xray | `ee3a03cbae656e2d6e6d81d7902ec712d08a345a` | 在已合并 v26.10.21 的 `8c864a52` 上适配共享 sing TLS 接口 |

## 本地功能与关键适配

- 动态入站接入上游 Scope 生命周期。每个节点拥有独立可取消作用域；移除节点会释放监听器和连接，失败的替换不覆盖原节点，反复增删不会在主作用域中积累旧节点清理引用。
- 保留各协议 AddUsers/DelUsers、面板用户映射、限速和流量统计。认证表按不可变快照发布，连接携带固定用户身份，删除用户后的旧认证会话需要重新经过撤销检查，已有 TCP/UDP 流会被关闭。删除前面的用户不会改变剩余用户的流量归属。
- 需要热更新的 VMess/VLESS、Hysteria 1/2、TUIC 服务端认证代码保存在 sing 内部兼容层，精确来源见该核心的 `internal/compat/UPSTREAMS.md`。保留上游线协议与许可证；VMess 更新用户不重置重放过滤器，动态加入 legacy 用户会启动密钥刷新。内部 Vision TLS 字段指针使用保留分配来源的 `unsafe.Add`。
- 保留 AnyTLS 已有会话、失败流、迟到流和关闭修复，适配新版 Start(stage, scope) 并保证关闭幂等。
- 保留 Naive 原生 padding 与浏览器普通 HTTPS 代理双模式、探测域名算法、404/407/204 语义、HTTP 转发头清理和每次 HTTP/2 写入刷新。用户变更继续采用原节点重建流程；已劫持的 HTTP/1 隧道也随节点关闭。
- REALITY 使用官方 v1.14.4 的 utls 后端，保留原 base64 密钥、短 ID、握手目标和本地 Xver 字段。VLESS/Vision、Trojan、AnyTLS 完成真实握手与回显验证。Xray 的 TLS 桥增加新版共享接口要求的握手超时读写及克隆保留。
- 保留每节点 EnableSniff、SniffOverrideDestination、DomainStrategy 和 UDP 域名解映射的执行顺序；端到端测试验证 HTTP 嗅探、域名覆盖、IPv4 解析和缓存请求内容均生效。
- 修复整项目回归暴露的 Xray 多路复用首流计数器竞争：节点计数器使用 LoadOrStore 原子发布，防止并发首流覆盖彼此的流量记录；原计费断言保留，并新增并发总量回归。
- N2X 适配证书注册表参数、Detour 字段位置、ConnectionTracker.RoutedFlow；TUN 未注册，现有 TCP/UDP 统计路径保留。Xray 的空 MinClientVer→0.0.0 兼容逻辑未改变。

## 验证范围

使用 Go 1.27.3、GOEXPERIMENT=jsonv2 和生产标签 `sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor`。

- N2X 全项目普通测试、全项目 race 与静态检查。
- sing-box 全仓包与测试的编译检查；定制路径、Scope 管理、认证撤销、Naive、AnyTLS、REALITY 与内部兼容层的 race 回归和静态检查。
- 官方公开模块客户端的七协议 TCP 并发用户变更、剩余用户流量归属、删除用户后已有/新连接拒绝；Hysteria 1/2、TUIC 原生 UDP 连通与撤销。
- REALITY 三协议真实握手和数据传输；VLESS Vision 使用未修改的官方客户端验证。该官方客户端的 uintptr 字段访问触发 checkptr，因此 Vision 公共客户端线协议测试单独在普通模式运行；本地服务端的指针修正另有 race/checkptr 回归，整项目 race 不关闭检查器。
- Xray ArtX、AnyTLS 接口、REALITY、SplitHTTP、Masque、XDrive 等相关路径 race 回归。
- Linux amd64、arm64、armv7 生产标签构建。

日志、精确版本、哈希及验证程序位于 `output/sing-1.14.4-migration-20261026/`。这里的验证不等于长期线上压力测试；未对 sing-box 全仓执行全部外网相关测试。

## 使用与回退

OriginalPath 自定义底层配置采用官方 1.14 格式：上游已移除旧 address 形式 DNS 服务器和旧顶层 dns.fakeip，使用这类历史配置时需要按 [官方迁移说明](https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats) 更新。本次保留 N2X 自身面板/本地节点字段；没有改写部署配置文件。

实际 `go.work` 仍选择 `../../Xray-core` 与 `../../sing-box_mod`，本地 `sing-box_mod-memory` 副本同步到同一 sing 提交。共享依赖采用 sing v0.9.7、sing-quic v0.7.2 开发固定版本及 sagernet/quic-go v0.61.0，精确伪版本见 UPSTREAMS.json 的 local_sync。

N2X 的已发布远端核心模块版本保留；当前新接口依赖本地 go.work，使用 GOWORK=off 或直接进行远端 CI/Docker 发布不能验证本次迁移。后续发布必须先推送两个核心提交，再固定新的远端模块版本并更新校验值。

迁移前的两个核心均保留 `backup/pre-sing-1.14.4-migration-20261026` 标签，分别指向 sing `77c9325a` 和 Xray `8c864a52`；sing 内存修复副本保留同名标签。N2X 原有未提交修改未被覆盖或提交，本次增量补丁和完整隔离检查点保存在上述输出目录，可按该增量回退 N2X 接口适配。
