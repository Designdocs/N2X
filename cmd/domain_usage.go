package cmd

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/spf13/cobra"
)

func init() {
	var day string
	cmd := &cobra.Command{Use: "domain-usage USER_ID [--day YYYY-MM-DD]", Short: "Query domain usage on this server", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		uid, err := strconv.Atoi(args[0])
		if err != nil || uid < 1 {
			return fmt.Errorf("用户 ID 须为正整数")
		}
		results, err := domainusage.LocalResults(domainusage.Directory(), uid, day)
		if err != nil {
			return err
		}
		period := day + " UTC"
		if day == "" {
			period = "近 30 天（UTC）"
		}
		for _, result := range results {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s · 节点 %v · 用户 #%d · %s\n", result.Panel, result.Nodes, uid, period)
			if len(result.Missing) > 0 {
				fmt.Fprintf(w, "数据不可用的节点：%v\n", result.Missing)
			}
			if len(result.Missing) == len(result.Nodes) {
				continue
			}
			printDomains(w, result.Rows)
		}
		return nil
	}}
	cmd.Flags().StringVar(&day, "day", "", "UTC calendar day")
	command.AddCommand(cmd)
}

func printDomains(w io.Writer, data map[string]domainusage.Row) {
	if len(data) == 0 {
		fmt.Fprintln(w, "此范围没有用户记录")
		return
	}
	rows := make([]domainusage.Row, 0, len(data))
	for _, r := range data {
		if r.Host != "" {
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Weighted == rows[j].Weighted {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].Weighted > rows[j].Weighted
	})
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "域名\t倍率流量（B）\t1 倍流量（B）\t连接数")
	var total, other domainusage.Row
	add := func(to *domainusage.Row, r domainusage.Row) {
		to.Raw += r.Raw
		to.Weighted += r.Weighted
		to.Connections += r.Connections
	}
	line := func(name string, r domainusage.Row) {
		fmt.Fprintf(table, "%s\t%.0f\t%d\t%d\n", name, r.Weighted, r.Raw, r.Connections)
	}
	for i, r := range rows {
		add(&total, r)
		if i < 20 {
			line(r.Host, r)
		} else {
			add(&other, r)
		}
	}
	if len(rows) > 20 {
		line("其他域名", other)
	}
	if r, ok := data[""]; ok {
		line("未识别域名", r)
		add(&total, r)
	}
	line("合计", total)
	table.Flush()
}
