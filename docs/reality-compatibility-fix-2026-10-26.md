# v0.17.11 REALITY/Vision 兼容修复

v0.17.10 升级后的 Xray REALITY 入站存在可复现的客户端兼容回归，暂停继续部署该版本。v0.17.11 恢复显式兼容配置原先接受的握手形式；现场连接恢复仍需在实际节点复测。

## 原因及复现

升级引入的 XTLS/REALITY `83f621788ca88b83179810b12baa7ae518aacb83` 在认证前要求 ClientHello 包含 X25519MLKEM768 密钥分享，即使已包含合法 X25519 分享、且配置了 `minClientVer=0.0.0`，仍会拒绝。

已发布依赖下的 N2X 实际 Xray 入站对照结果：

| 客户端与握手 | v0.17.10 | 修复后 |
| --- | --- | --- |
| sing REALITY，普通 VLESS / Vision | REALITY 认证前失败 | 通过 |
| 新版 Xray，默认 chrome 指纹 / Vision | 通过 | 通过 |
| 同一新版 Xray，既有 hellochrome_120 指纹 / Vision | 失败 | 通过 |
| sing / Xray，通过 Vision 传输内层 TLS 1.3 HTTPS 大响应 | sing 失败 | 通过 |
| 错误 short ID | 拒绝 | 仍拒绝 |

客户端程序更新不会强制替换已选择的握手指纹，因此“软件最新版”不能排除此回归。测试使用本地 TLS 伪装目标、随机 X25519 密钥和真实 VLESS 数据传输，不依赖远端节点或真实用户密钥。

两条 `freedom.domainStrategy` 消息属于上游兼容迁移警告，不是上述认证前失败原因。缺少 `/run/N2X/.env` 后回退 config.json 的提示也不能单独解释断连。

## 修复及范围

Xray 固定修复提交：`ab4e19cf229e6af0aa211e70cde1f913437da0d1`；正式模块 `v0.0.0-20261026125017-ab4e19cf229e`。

- 将所用 REALITY 源码固定在 Xray 的 `internal/compat/reality`，保留原许可证、原提交和逐文件来源摘要，避免依靠本地模块替换才能修复。
- 只有显式 `minClientVer=0.0.0` 才允许原有 X25519-only 形式。其他配置继续采用混合分享要求；错误长度、重复分享和错误顺序仍拒绝。
- 私钥、SNI、short ID、时间、版本、TLS 与 VLESS 用户校验继续生效。新混合握手的认证密钥选择保持一致。
- N2X 生成的 freedom 出站和示例使用 `streamSettings.sockopt.domainStrategy`。已部署的自定义 JSON 未自动改写；若其中仍有旧字段，警告可能继续出现，上游仍会兼容迁移。
- sing-box_mod 继续固定 `9b671548395f8ce1ed6c169f465daf97ea567b2f`，保留现有 Naive、AnyTLS 和动态用户功能。

此修复作用于 Xray REALITY 的 TCP、gRPC 和 XHTTP 共用服务端路径；新增端到端重点覆盖用户报告的 TCP VLESS REALITY/Vision。普通 TLS、AnyTLS 和 Naive 使用既有全项目回归确认。

## 验证与交付

核验下载后的 1,199 个 Xray Go/模块/来源文件与已审查提交一致。Xray 全包编译、受影响传输/VLESS/兼容路径 race 与静态检查已完成；MASQUE 上游测试有一处 XMUX 参数类型不匹配，已适配指针参数，未修改其运行时实现。

正式远端依赖使用 `GOWORK=off` 和生产完整构建标签验证。回归日志与精确结果位于 `output/vless-reality-investigation-20261026/`，包括失败基线、修复后的真实握手、N2X 全项目普通/race/vet、无外网 Linux Xray 测试和来源核验。公共 Vision 客户端的指针访问限制使该线协议测试只在普通模式运行；服务端与其他测试保留 race 检查。

安装包输出到 `output/releases/v0.17.11/`，源码身份、三个 Linux 架构、固定依赖、ZIP 和摘要以生成的 `release-manifest.json` 为准。v0.17.10 产物保留原始内容和哈希并标记暂停部署，避免同版本二进制发生变化。

完成本地验证后可在单节点恢复灰度。保留当前配置和可工作的旧程序，停止旧进程后切换，验证实际客户端的 HTTPS、上下行统计和重连；同一节点编号只运行一套后端。当前没有代替用户部署生产节点，也没有将本地通过视为现场恢复确认。
