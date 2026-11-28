package cmd

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/common/domainusage"
)

func TestDomainUsageGBTable(t *testing.T) {
	for bytes, want := range map[float64]string{0: "0 GB", 1: "<0.000001 GB", 8896: "0.000008 GB", 74548790: "0.069429 GB", 1 << 30: "1 GB", 1.25 * (1 << 30): "1.25 GB"} {
		if got := trafficGB(bytes); got != want {
			t.Errorf("%v bytes: %q, want %q", bytes, got, want)
		}
	}
	data := map[string]domainusage.Row{
		"chatgpt.com": {Host: "chatgpt.com", Raw: 74548790, Weighted: 149097580, Connections: 1248},
		"":            {Raw: 8896, Weighted: 0, Connections: 1},
	}
	var out bytes.Buffer
	printDomains(&out, data)
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := [][4]string{
		{"域名", "汇聚", "默认", "连接数"},
		{"chatgpt.com", "0.138858 GB", "0.069429 GB", "1248"},
		{"未识别域名", "0 GB", "0.000008 GB", "1"},
		{"合计", "0.138858 GB", "0.069437 GB", "1249"},
	}
	if len(lines) != len(want) {
		t.Fatal(out.String())
	}
	// Fixed independently in screen cells: columns start at 0, 13, 26, 39.
	for i, row := range want {
		line := lines[i]
		cells := 0
		for j, field := range row {
			pos := strings.Index(line, field)
			if pos < 0 || strings.TrimSpace(line[:pos]) != "" {
				t.Fatalf("missing %q in %q", field, lines[i])
			}
			cells += pos
			if cells != [4]int{0, 13, 26, 39}[j] {
				t.Fatalf("%s starts at %d in %q", field, cells, lines[i])
			}
			cells += len([]rune(field))
			for _, r := range field {
				if r > 127 {
					cells++
				}
			}
			line = line[pos+len(field):]
		}
		if line != "" {
			t.Fatal(line)
		}
	}
}

var domainANSI = regexp.MustCompile(`\x1b\[[0-9;]+m`)

func TestDomainUsageNarrowTerminal(t *testing.T) {
	host := strings.Repeat("longdomain.", 8) + "com"
	rows := [][4]string{{"域名", "汇聚", "默认", "连接数"}, {host, "0.138858 GB", "0.069429 GB", "1248"}, {"合计", "0.138858 GB", "0.069429 GB", "1248"}}
	for _, cols := range []int{80, 42, 20, 14} {
		var out bytes.Buffer
		writeDomainTable(&out, rows, cols, true)
		if strings.Count(out.String(), "\x1b[36m") == 0 || !strings.HasPrefix(out.String(), "\x1b[36m") {
			t.Fatal("missing header color")
		}
		var plain bytes.Buffer
		writeDomainTable(&plain, rows, cols, false)
		if domainANSI.ReplaceAllString(out.String(), "") != plain.String() {
			t.Fatalf("color changed table layout at %d columns", cols)
		}
		if cols == 80 {
			for _, cell := range []string{"\x1b[1;33m合计", "\x1b[36m0.138858 GB", "\x1b[35m0.069429 GB", "\x1b[32m1248"} {
				if !strings.Contains(out.String(), cell+"\x1b[0m") {
					t.Fatalf("missing total cell %q", cell)
				}
			}
		}
		// Strip ANSI and whitespace. Wrapping must keep every hostname character.
		var allHost strings.Builder
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.Contains(line, "\x1b") && strings.Contains(line, "long") {
				t.Fatal("colored data", line)
			}
			s := domainANSI.ReplaceAllString(line, "")
			if domainCellWidth(s) > cols {
				t.Fatalf("line exceeds %d cells: %q", cols, s)
			}
			// Host is the only field containing lowercase letters.
			for _, r := range strings.Fields(s) {
				if r[0] >= 'a' && r[0] <= 'z' || r[0] == '.' {
					allHost.WriteString(r)
				}
			}
		}
		if allHost.String() != host {
			t.Fatalf("hostname lost in %d columns: %s", cols, allHost.String())
		}
	}
}

func TestDomainStatusColors(t *testing.T) {
	for _, tc := range []struct {
		used, free int64
		state      string
		want       []string
	}{
		{72 << 10, 2 << 30, "active", []string{"\x1b[36m72 KiB", "\x1b[32m2 GiB", "\x1b[32m采集中"}},
		{domainusage.MaxDiskBytes, domainusage.MinFreeBytes, "disk space", []string{"\x1b[31m128 MiB", "\x1b[31m1 GiB", "\x1b[31m自动暂停"}},
		{-1, domainusage.ResumeFreeBytes - 1, "manual", []string{"\x1b[33m未知", "磁盘可用：\x1b[33m", "\x1b[33m手动关闭"}},
		{0, domainusage.ResumeFreeBytes, "waiting", []string{"磁盘可用：\x1b[32m", "\x1b[33m等待节点就绪"}},
		{0, -1, "", []string{"磁盘可用：\x1b[33m未知", "\x1b[33m状态暂不可用"}},
	} {
		var plain, colored bytes.Buffer
		states := []domainusage.InstanceState{{State: tc.state}}
		writeDomainStatus(&plain, tc.used, tc.free, states, false)
		writeDomainStatus(&colored, tc.used, tc.free, states, true)
		if domainANSI.ReplaceAllString(colored.String(), "") != plain.String() {
			t.Fatal(colored.String())
		}
		for _, value := range tc.want {
			if !strings.Contains(colored.String(), value) {
				t.Errorf("missing %q in %q", value, colored.String())
			}
		}
	}
}
