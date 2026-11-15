# TUIC 预读缓存与关闭竞态

## 触发与修复

TUIC 请求头与首段业务数据一起到达时，定制核心的 `internal/compat/singquic/tuic/service.go` 曾使用共享依赖的 `bufio.CachedConn` 保留预读数据。用户热更新撤销、上下文取消和路由结束都可能关闭该连接；关闭与读取同时访问、释放同一缓存，导致 race。

修复位于 sing-box 定制核心的三个文件：

- `internal/compat/singquic/tuic/service.go`：改用 TUIC 自己的预读包装。
- `internal/compat/singquic/tuic/buffered_conn.go`：复制并持有少量预读数据；短锁保护缓存游标和关闭标记。底层读取、关闭在锁外执行，使 Close 能唤醒阻塞读取。关闭后不再交付缓存数据。
- `internal/compat/singquic/tuic/buffered_conn_test.go`：验证缓存独立所有权、分段读取顺序、空读取、阻塞读取唤醒、多读取/多关闭并发。

TUIC 请求头和线协议不变；已有用户撤销、保留用户的 TCP/UDP 连接、限速和计费继续使用既有路径。

## 本地验收

先用只包含 N2X 和本地定制核心的临时 Go workspace，避免带入其他核心的开发改动。外置盘路径使用 realpath，并在 go.work 中为带空格的路径加引号。

```sh
GOEXPERIMENT=jsonv2 GOWORK=/absolute/path/to/local.go.work go test -race -mod=readonly -count=5 ./internal/compat/singquic/tuic ./common/dynamicuser
```

上面命令从定制核心目录运行。N2X 目录执行：

```sh
GOEXPERIMENT=jsonv2 GOWORK=/absolute/path/to/local.go.work go test -race -mod=readonly -count=5 -tags 'sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./core/sing -run '^TestUpstreamClientsSurviveUserReindexAndRevoke/tuic$'
GOEXPERIMENT=jsonv2 GOWORK=/absolute/path/to/local.go.work go test -race -mod=readonly -tags 'sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./...
```

2026-11-15：修复前固定依赖的原用例复现 race；修复后原用例连续五轮通过，核心两包五轮 race 通过，N2X 完整生产标签的 19 个测试包 race 通过。

## 正式依赖与交付

修复核心提交为 `a970e771f45b2ead99db9108562d3ea727fcbf51`，N2X 的 `go.mod`、`go.sum`、`UPSTREAMS.json` 同步固定为 `v1.13.0-alpha.5.0.20261115142134-a970e771f45b`。使用 `GOWORK=off` 的正式构建直接引用包含修复的远端核心，无需依赖本地 workspace。

此前的 `tuic-race-fix-local` 程序用于验证修复；正式交付使用干净 N2X 提交重新打包，并核对模块版本、二进制来源和实际下载附件。

正式模式回归入口（从 N2X 目录运行）：

```sh
GOEXPERIMENT=jsonv2 GOWORK=off go test -race -mod=readonly -tags 'sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./...
```

所有测试、构建和运行检查仅在本地执行。


本地验证产物位于外置盘 `Builds/N2X/tuic-race-fix-20261115/`：macOS ARM64、Linux amd64/ARM64/ARMv7 均已完成构建。Linux ARM64 无外网容器中的 26 个用例（含子用例）覆盖缓存、注册表撤销、七协议用户热更新、TCP/UDP、计费及动态限速；三个 Linux 验证程序的版本、有效配置和无效配置退出检查均通过。amd64、ARMv7 运行使用本机架构模拟。构建清单及逐项结果见该目录的 `build-manifest.json`、`verification.json`。

正式远端依赖模式（`GOWORK=off`）下，完整生产标签的 19 个测试包和 19 包 race 已通过。race 首轮的 Shadowsocks 测试遇到临时 UDP 端口占用，保留该日志并仅重跑 sing 包后通过；其他 18 包未重复运行。
