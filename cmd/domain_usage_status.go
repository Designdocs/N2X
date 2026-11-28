package cmd

import (
	"fmt"
	"io"
	"strconv"

	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/spf13/cobra"
)

func init() {
	command.AddCommand(&cobra.Command{
		Use: "domain-usage-status", Short: "Show local domain statistics storage and collector state", Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			dir := domainusage.Directory()
			used, free := domainusage.StorageUsage(dir)
			writeDomainStatus(cmd.OutOrStdout(), used, free, domainusage.InstanceStates(dir))
		},
	})
}

func storageSize(n int64) string {
	if n < 0 {
		return "未知"
	}
	for _, unit := range []struct {
		size  int64
		label string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}, {1, "B"}} {
		if n >= unit.size || unit.size == 1 {
			prec := 2
			if n%unit.size == 0 {
				prec = 0
			}
			return strconv.FormatFloat(float64(n)/float64(unit.size), 'f', prec, 64) + " " + unit.label
		}
	}
	return "0 B"
}

func stateLabel(state string) string {
	switch state {
	case "active":
		return "采集中"
	case "waiting":
		return "等待节点就绪"
	case "manual":
		return "手动关闭"
	case "disk space":
		return "自动暂停 · 磁盘空间不足，达到 " + storageSize(domainusage.ResumeFreeBytes) + " 后自动恢复"
	case "daily capacity":
		return "自动暂停 · 统计存储额度不足，下一个 UTC 日期重试"
	case "in-memory capacity":
		return "自动暂停 · 内存统计条目已满，下个整点重试"
	case "storage full":
		return "自动暂停 · 文件系统空间已满"
	case "storage error":
		return "自动暂停 · 统计目录读写失败"
	default:
		return "状态暂不可用"
	}
}

func writeDomainStatus(w io.Writer, used, free int64, states []domainusage.InstanceState) {
	fmt.Fprintf(w, "统计占用：%s / %s\n磁盘可用：%s\n", storageSize(used), storageSize(domainusage.MaxDiskBytes), storageSize(free))
	if len(states) == 0 {
		fmt.Fprintln(w, "运行状态：未连接到统计服务")
		return
	}
	for _, state := range states[1:] {
		if state.State != states[0].State {
			fmt.Fprintln(w, "运行状态：")
			for _, s := range states {
				if s.Node > 0 {
					fmt.Fprintf(w, "  %s #%d · %s\n", s.Panel, s.Node, stateLabel(s.State))
				} else {
					fmt.Fprintln(w, "  "+stateLabel(s.State))
				}
			}
			return
		}
	}
	fmt.Fprintln(w, "运行状态："+stateLabel(states[0].State))
}
