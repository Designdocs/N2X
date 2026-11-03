# 定时重启

默认关闭，旧配置省略整段也保持关闭。更新到支持此功能的二进制后，在 `/etc/N2X/config.json` 顶层手动添加以下配置开启。程序自带示例使用 `Enabled: false`；管理脚本的配置向导只写入使用说明，避免在旧二进制上生成不识别的字段。

```json
"ScheduledRestart": {
  "Enabled": true,
  "IntervalDays": 3,
  "StartTime": "03:00",
  "EndTime": "05:00",
  "Timezone": "Asia/Shanghai"
}
```

- `IntervalDays`：1–3650，默认 3。开启或调整计划后至少运行 `3 × 24` 小时，再在首个可用夜间窗口内随机选择一分钟。若满 72 小时是在白天，会等到下一次夜间窗口；若是在窗口中间，只从剩余的整分钟中选择。
- `StartTime` / `EndTime`：同一天的 `HH:MM`，默认 `03:00`–`05:00`，包含开始、不含结束。结束必须晚于开始，不支持跨午夜窗口。按窗口随机错开各台机器的重启时间。
- `Timezone`：留空使用服务器时区；需要北京时间时填 `Asia/Shanghai`。支持 IANA 时区名称，二进制包含时区数据。

启用后日志的 `Scheduled restart planned` 会显示下一次重启时间（包含 UTC 偏移）。未修改计划字段的配置/DNS 热重载保留原定时间；更改计划字段、关闭后再开启或进程重新启动会重新计时。重启后的内存已释放，因此不把旧计划写到磁盘。系统休眠或时钟变化导致错过窗口时，会等待下一个可用窗口，不在白天补重启。夏令时跳过的分钟不会被选中。

定时任务与内存保护共用每 5 秒一次的退出检查，内存保护仍可随时触发，不受夜间窗口限制。触发定时重启后，整个 N2X 进程退出，所有核心和节点的现有连接会中断；先正常清理，最多等待 10 秒，再强制以状态 1 退出。自动拉起依赖服务管理器：安装脚本的 systemd 服务使用 `Restart=always` 和 `RestartSec=10`，手动运行或容器需要配置相应重启策略。

安装脚本会把源配置渲染为 `/run/N2X/config.json`。修改 `/etc/N2X/config.json` 后执行 `systemctl restart N2X` 重新渲染；直接运行 `N2X server -c ...` 时，开启文件监控可热重载这些字段。旧二进制需要更新后才支持新配置。

## 现有内存保护

默认 `Memory.SoftLimitPercent=70`、`Memory.RestartPercent=90`，省略也会启用。后者检查宿主机 `(Total - Available) / Total`，包含同机其它进程的占用，并非仅检查 N2X RSS；可回收缓存计入可用内存。达到阈值时记录诊断数据并退出，由管理器重启。详见 [内存压力保护](memory-protection.md)。

## Geo 下载计划

当前安装脚本向 crontab 写入每周六服务器时间 04:00 的任务：

```cron
0 4 * * 6 /usr/bin/N2X update geodata -r >/var/log/N2X-geodata.log 2>&1
```

`N2X update geodata` 独立更新 `/etc/N2X/geoip.dat` 和 `/etc/N2X/geosite.dat`，不安装或升级程序。数据源沿用发行包使用的 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)：先获取 `release` 分支的提交，再从同一提交下载两份数据和 SHA-256 校验文件。全部校验通过才替换，下载或校验失败保留原数据。

`-r` / `--restart` 表示数据变化后重启正在运行的 N2X，让新数据生效；数据相同则不重启，停止中的服务不会被自动启动。不带 `-r` 只更新磁盘文件，下次启动或重启生效。替换失败或重启命令失败时恢复旧文件；已尝试重启的服务会使用旧文件重新启动。单个文件通过同文件系统内重命名替换，更新期间使用排他锁阻止重复执行。优先使用 `flock`，退出（包括 OOM/SIGKILL）由系统释放；未安装 `flock` 时使用目录锁，正常退出和 INT/TERM 会清理，强制杀死后可能需清理日志提示的遗留锁目录。

需要升级管理脚本及新增的 `geodata.sh` 模块后，旧的周六任务才会正常工作；Geo 修复不要求升级 N2X 二进制。安装和 `N2X update_shell` 都会安装该模块；从旧脚本升级时若模块尚未下载，首次执行 Geo 更新会补装。原缺陷是管理脚本把 `geodata` 当作版本号，并丢弃 `-r`；修复后单独分发 Geo 参数，同时兼容每月全程序更新使用的 `N2X update -r`。安装器只补充缺失或空的 Geo 文件，程序升级会保留已有的独立更新或自定义数据。

自定义 Xray `AssetPath` 时，可通过 `N2X_GEODATA_DIR=/实际路径 N2X update geodata -r` 更新对应目录，并在 cron 中设置相同变量。`N2X_GEODATA_REVISION` 可选填 40 位提交 SHA 固定数据版本；默认跟随 `release` 分支。数据提交记录在目标目录的 `geodata.revision.txt`。
