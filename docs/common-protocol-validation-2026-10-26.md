# v0.17.12 常用协议验证与修复

扩展真实连接和并发测试后，额外发现并修复了四类问题。最终固定远端依赖下的 N2X 全量普通测试、race、静态检查，以及无外网 Linux 双核心测试均通过。v0.17.12 可进入单节点灰度复测；尚未验证用户现场恢复或长期生产负载。

## 已修复的问题

| 问题 | 影响路径 | 修复与证据 |
| --- | --- | --- |
| TLS 证书选择与 OCSP/证书更新并发读写 | Xray 使用普通 TLS 证书的协议 | 证书列表受同步保护，已发布证书保持不可变，每个监听配置拥有独立原始证书；并发读取、热更新及快照保持测试通过 |
| WS 正常关闭被当作传输错误，丢弃排队响应尾部 | Xray 的 WS 传输 | 正常关闭 1000/1001 映射 EOF，保留同次读取返回的数据；协议错误仍上报。Linux 旧路径多次出现 376,832 字节响应只收到 366,899 字节，修复后连续 10 轮、每轮 3 次 HTTPS 请求通过 |
| gRPC CloseSend 与 Send 并发 | Xray gRPC 客户端/出站封装，单流与多流 | 先取消阻塞发送，再串行关闭；关闭幂等，关闭后的写入拒绝。真实 gRPC 单流/多流与专门的阻塞发送关闭回归通过 |
| AnyTLS 流关闭错误状态并发读写 | sing AnyTLS 共用会话，入站和出站 | 固定 v0.0.11 的客户端/会话源码并以原子指针发布关闭错误；保留帧、填充、池、动态用户及既有 FIN 清理机制 |

这些缺陷由扩展测试暴露，不能全部归因于本次上游合并。原先的 REALITY X25519-only 客户端兼容修复继续保留，参见 [REALITY 修复说明](reality-compatibility-fix-2026-10-26.md)。v0.17.10 和仅含 REALITY 修复的本地 v0.17.11 候选包均暂停继续部署。

## 实际连接覆盖

| 核心与协议 | 验证内容 | 结果 |
| --- | --- | --- |
| Xray VLESS REALITY/Vision | 独立 sing 客户端、新 Xray 默认及既有指纹，内层 TLS 1.3 HTTPS 大响应，错误 short ID | 通过 |
| Xray VLESS 普通 TLS | TCP、Vision、WS、gRPC 单流/多流、HTTPUpgrade、XHTTP packet-up/stream-one；每组合三次 HTTPS 与用户流量归属 | 通过 |
| Xray AnyTLS TLS/REALITY | 独立公共客户端、并发 HTTPS、新会话重连、上下行统计、错误密码、用户删除/恢复、剩余用户可用性 | 通过 |
| Xray VMess/Trojan/Shadowsocks | 独立客户端的 VMess AEAD 及 TLS、Trojan TLS、Shadowsocks AES-128-GCM；实际 HTTPS 与用户统计 | 通过 |
| sing Naive | 实际 TLS 入站，浏览器 HTTP/1.1 和 HTTP/2 CONNECT，独立填充线协议的前八帧及后续直传，错误认证、用户重建及统计身份 | 通过 |
| sing 其他既有协议 | 公共客户端七协议 TCP，Hysteria 1/2 和 TUIC 原生 UDP，用户重排/撤销；既有 AnyTLS、在线状态和内存清理回归 | 通过 |

Naive 使用协议客户端验证，没有运行 Chromium/Cronet 原生应用或 Naive HTTP/3。其用户集合变化仍会重建监听并中断既有连接，这是原有机制；重建后的剩余用户和恢复用户均已验证。

公共 AnyTLS v0.0.11 客户端本身也会触发相同关闭竞争。普通测试保留独立公共客户端；race 测试使用修复后的共享客户端，执行相同场景，避免客户端缺陷掩盖服务端结果。公共 Vision 客户端的指针访问限制仍按原边界在普通模式测试；新增 VLESS TLS 各传输用例已启用 race。

## 固定源码与检查

- Xray：`8dd8598eb617f0220613994feaf951d4c56d43c0`，模块 `v0.0.0-20261026134447-8dd8598eb617`。
- sing：`1c83277a4b98bd6fdf95e12cca1c65c8fbad9940`，模块 `v1.13.0-alpha.5.0.20261026134445-1c83277a4b98`；本地内存修复副本已快进到同一提交。
- 下载模块的 1,203 个 Xray 文件和 1,218 个 sing 文件与已验证源码一致；单独的嵌套测试模块不属于发布模块。
- `GOWORK=off`、生产完整标签的 N2X 全量普通/race/vet 均通过；Naive 和修复后的 AnyTLS 依赖 race 通过。
- 无外网 Linux arm64 容器运行 Xray 和 sing 全包测试均通过。两核心全包编译、受影响路径的专门回归及静态检查通过。
- 未通过依赖外网的上游 `TestECHDial`（外部 DNS/ECH 返回无效配置），不将其计入通过项；N2X 自身 ECH 配置映射测试和本地握手回归通过。

完整日志及来源核验位于 `output/common-protocol-verification-20261026/`。保留初次失败的 race、Linux WS 记录和修复后的结果，没有放宽流量、认证或响应完整性断言。

## GitHub 构建与上线边界

测试通过后，使用现有 `Build and Release` 工作流构建 `v0.17.12`，选择 Linux amd64、arm64、armv7。构建校验固定内核版本、源码提交和干净状态，安装 ZIP 附校验摘要及二进制构建信息；下载后再核验版本、架构和模块身份。

用户明确授权推送后通过现有工作流直接发布 Linux，使用 `publish_release=true`、`targets=linux`，创建版本标签与 GitHub Release 并上传三个 Linux 安装包及摘要；不执行生产节点部署。构建任务、Release 和下载产物的最终状态以验证记录为准。建议单节点先验证真实客户端 HTTPS、上下行统计和重连，再观察长期内存与连接数。
