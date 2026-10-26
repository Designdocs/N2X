# 2026-10-26 上游内核稳定更新记录

本文记录第一轮兼容修复回移；随后已完成 [sing-box v1.14.4 完整迁移](sing-box-1.14.4-migration-2026-10-26.md)，当前核心版本及验证结果以新记录为准。

已把经过验证的更新同步到现有本地核心目录，保留原分支与提交历史。此次仅做本地更新，没有推送、发布版本或部署节点。

| 项目 | 上游核查与处理 | 本地提交 |
| --- | --- | --- |
| Xray | 合并官方正式版 [v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21)，源提交 `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74` | `8c864a52ead81251425f4f7499e0c539bca93eaf` |
| sing-box | 保留现有定制基线，回移官方稳定版中的 [Go 1.27 HTTP/2 修复](https://github.com/SagerNet/sing-box/commit/f50ca2244b6d7bb592a1d088e7d32bd252721ed9)，并适配共享的新版 REALITY | `77c9325a6e2b8ea040b1a45047abd54719571329` |

`wyx2685/Xray-core` 的最新提交为 `e087e74a`，基于预发布 v26.9.30；本次选择官方已标记为非预发布的 v26.10.21。Xray 合并提交的两个父提交分别是原本地 `56ad0ec0` 和官方正式版提交，原本地历史完整保留。

`wyx2685/sing-box_mod` 的 `dev-next` 仍为 `8d054dcd`，日期为 2025-12-02。官方 [sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) 已发布，但整体合并涉及 865 个提交、1267 个文件和 138 个冲突路径，覆盖动态用户 API、TLS、路由及 Naive。此次采用必要的稳定修复回移，未将整个定制内核替换为 v1.14.4。

## 保留和适配的功能

- 保留 ArtX 认证、wire 版本、流控、原生 UDP、目标就绪通知及已有回落语义。
- 保留 wyx AnyTLS/TUIC、各协议动态增删用户，以及本地 XMUX 锁复制修复；适配官方 FinalMask 和新调用者。
- 保留 WebSocket/XHTTP 每个监听器独立的回落配置，包括空值关闭、缺省继承环境的区别；根据原 `.proto` 重新生成代码。
- Go 1.27 的反向代理会拒绝 CONNECT；为 ArtX 恢复仅指向配置源站的受限回落，继续限制响应大小、等待时间并清除认证及跳跃头。
- Go 1.27 的 HTTP/2 入口会清除连接期限；保留 ArtX 原解析预算及源站请求预留时间，原超时测试断言没有放宽。
- sing 的 Naive 双客户端模式、探测域名算法、HTTP/2 刷新和 AnyTLS 会话/失败流清理代码均与 `3686e55b` 一致。
- sing 的 REALITY 继续接受原 base64 私钥配置，转换为新版 X25519 密钥对象；固定向量验证公钥身份、握手地址、服务名和短 ID。
- N2X 的空 `MinClientVer` 归一化为 `0.0.0` 的兼容逻辑及回归测试保持不变。

## 本地集成

N2X 的 `go.work` 选择以下实际源码目录：

| 模块 | 本地目录 |
| --- | --- |
| `github.com/xtls/xray-core` | `/Users/admin/Desktop/X/Xray-core` |
| `github.com/sagernet/sing-box` | `/Users/admin/Desktop/X/sing-box_mod` |

工作区内的 `sing-box_mod-memory` 副本也已同步到同一个 sing 提交。N2X、Docker 和现有工作流的 Go 构建版本已对齐到 1.27.3，配置检查适配了该版本的 JSON API。

`go.mod` 中已发布的远端核心替换版本暂时保留；本地更新通过 `go.work` 生效。后续发布需先推送两个核心的新提交，再更新 N2X 的正式模块固定版本和校验值。使用 `GOWORK=off` 会选择原已发布核心，不用于验证此次本地更新。

## 验证与产物

已完成生产双核心标签下的 N2X 全量测试、相关包 race 回归、N2X 全项目静态检查、Xray 定制路径静态检查和 ArtX 配置回归。Reality 旧客户端兼容、Naive 原生/浏览器路径、AnyTLS 清理、在线设备和内存保护均在验证范围内。

Linux amd64、arm64、armv7 的验证程序位于 `output/upstream-sync-20261026/`，使用 `local-stable-sync-20261026` 本地版本名。对应目录保存测试、race、构建日志及合并隔离副本。验证程序没有作为正式安装包发布。

Xray 全仓单元测试中的 geodata 外部数据依赖不属于此次“全量 N2X”验证；Xray 验证覆盖本地扩展、相关传输和 ArtX 配置路径。

## 回退基线

各目录已先创建回退标签：

- Xray：`backup/pre-stable-sync-20261026-56ad0ec0`。
- 原 sing 目录：`backup/pre-stable-sync-20261026-0ce2158a`。
- sing 内存修复副本：`backup/pre-stable-sync-20261026-3686e55b`。

原 sing 目录之前落后于已发布的 AnyTLS 内存修复，因此同时包含了已有 `3686e55b` 修复；本次兼容更新建立在该修复之上。
