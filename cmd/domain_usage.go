package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	table := [][4]string{{"域名", "汇聚", "默认", "连接数"}}
	var total, other domainusage.Row
	add := func(to *domainusage.Row, r domainusage.Row) {
		to.Raw += r.Raw
		to.Weighted += r.Weighted
		to.Connections += r.Connections
	}
	line := func(name string, r domainusage.Row) {
		table = append(table, [4]string{name, trafficGB(r.Weighted), trafficGB(float64(r.Raw)), strconv.FormatInt(r.Connections, 10)})
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
	var columns int
	var color bool
	if file, ok := w.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		columns, _, _ = term.GetSize(int(file.Fd()))
		color = os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == ""
	}
	writeDomainTable(w, table, columns, color)
}

// Match the panel's 1024-based GB conversion, including for sub-megabyte rows.
func trafficGB(bytes float64) string {
	gb := bytes / (1 << 30)
	if gb > 0 && gb < 0.000001 {
		return "<0.000001 GB"
	}
	n := strconv.FormatFloat(gb, 'f', 6, 64)
	return strings.TrimRight(strings.TrimRight(n, "0"), ".") + " GB"
}

// Stored hostnames and formatted numbers are ASCII. The Chinese headings and
// summary labels each use two terminal cells per Han character.
func runeCells(r rune) int {
	if unicode.Is(unicode.Han, r) {
		return 2
	}
	return 1
}

func domainCellWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeCells(r)
	}
	return n
}

func splitDomainCell(s string, maxCells int) (string, string) {
	n := 0
	for i, r := range s {
		n += runeCells(r)
		if n > maxCells {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

func writeDomainTable(w io.Writer, rows [][4]string, terminalWidth int, color bool) {
	const gap = 2
	var widths [4]int
	for _, row := range rows {
		for i, cell := range row {
			widths[i] = max(widths[i], domainCellWidth(cell))
		}
	}
	// Wrap the domain first. On especially narrow terminals wrap the other
	// columns too, keeping the full values and a stable start for each column.
	if terminalWidth >= len(widths)*2+(len(widths)-1)*gap {
		over := widths[0] + widths[1] + widths[2] + widths[3] + 3*gap - terminalWidth
		for over > 0 {
			i := 0
			if widths[0] <= 2 {
				for j := 1; j < len(widths); j++ {
					if widths[j] > widths[i] {
						i = j
					}
				}
			}
			delta := min(over, widths[i]-2)
			widths[i] -= delta
			over -= delta
		}
	}
	for index, row := range rows {
		for row != ([4]string{}) {
			var parts [4]string
			last := 0
			for i, cell := range row {
				parts[i], row[i] = splitDomainCell(cell, widths[i])
				if parts[i] != "" {
					last = i
				}
			}
			var line strings.Builder
			for i, part := range parts[:last+1] {
				line.WriteString(part)
				if i < last {
					line.WriteString(strings.Repeat(" ", widths[i]-domainCellWidth(part)+gap))
				}
			}
			if index == 0 && color {
				fmt.Fprintf(w, "\x1b[36m%s\x1b[0m\n", line.String())
			} else {
				fmt.Fprintln(w, line.String())
			}
		}
	}
}
