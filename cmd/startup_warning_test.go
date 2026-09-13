package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/node"
)

var dnsWarning = conf.Issue{
	Path:    "Cores[0].DnsConfigPath",
	Message: "/etc/N2X/dns.json: invalid JSON at line 1, column 14 (ignored: xray runs with its default DNS settings)",
	Kind:    conf.IssueSyntax,
}

func TestStartupReportShowsWarningsOnTheirOwn(t *testing.T) {
	var report startupReport
	report.addWarnings([]conf.Issue{dnsWarning})

	lines := report.render(startupReportTitle, "核心与节点均已启动", "")
	text := strings.Join(lines, "\n")
	for _, want := range []string{
		"N2X 启动警告摘要",
		"共 1 项：警告 1",
		"[警告] [格式错误] Cores[0].DnsConfigPath: /etc/N2X/dns.json: invalid JSON at line 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary does not mention %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "错误摘要") {
		t.Errorf("a report with only warnings is titled as errors:\n%s", text)
	}
}

func TestStartupReportListsWarningsAfterErrors(t *testing.T) {
	var report startupReport
	report.addWarnings([]conf.Issue{dnsWarning})
	report.addNodeFailures(
		[]conf.NodeConfig{{ApiConfig: conf.ApiConfig{NodeType: "vless", NodeID: 1}}},
		[]node.StartFailure{{Index: 0, Stage: node.StagePanel, Err: os.ErrDeadlineExceeded}},
	)

	lines := report.render(startupReportTitle, "", "")
	text := strings.Join(lines, "\n")
	panelLine := lineIndex(lines, "[面板错误] Nodes[0] (vless #1)")
	warning := lineIndex(lines, "[警告] [格式错误] Cores[0].DnsConfigPath")
	if panelLine < 0 || warning < 0 || warning < panelLine {
		t.Fatalf("want the error first and the warning after it:\n%s", text)
	}
	for _, want := range []string{"N2X 启动错误摘要", "共 2 项：面板错误 1，警告 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary does not mention %q:\n%s", want, text)
		}
	}
}

// A rejected config still shows the warnings found next to its errors.
func TestStartupReportKeepsWarningsOfARejectedConfig(t *testing.T) {
	var report startupReport
	report.addConfigError(&conf.ValidationError{
		File:     "/etc/N2X/config.json",
		Issues:   []conf.Issue{{Path: "Nodes[0].NodeTyp", Message: "unknown key"}},
		Warnings: []conf.Issue{dnsWarning},
	})
	text := strings.Join(report.render(startupReportTitle, "", ""), "\n")
	for _, want := range []string{"[配置错误] Nodes[0].NodeTyp", "[警告] [格式错误] Cores[0].DnsConfigPath"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary does not mention %q:\n%s", want, text)
		}
	}
}

// writeConfigWithBrokenDNS writes the valid test config with an xray DNS
// file that is not valid JSON.
func writeConfigWithBrokenDNS(t *testing.T) string {
	t.Helper()
	dns := filepath.Join(t.TempDir(), "dns.json")
	if err := os.WriteFile(dns, []byte(`{"servers": [}`), 0o600); err != nil {
		t.Fatalf("write dns: %v", err)
	}
	return writeTestConfig(t, strings.Replace(validTestConfig,
		`"Cores": [{"Type": "xray"}]`, `"Cores": [{"Type": "xray", "DnsConfigPath": "`+dns+`"}]`, 1))
}

func TestCheckConfigPassesWithWarnings(t *testing.T) {
	var out strings.Builder
	if err := checkConfig(writeConfigWithBrokenDNS(t), &out); err != nil {
		t.Fatalf("a DNS file problem failed the check: %v\n%s", err, out.String())
	}
	for _, want := range []string{"WARNING", "Cores[0].DnsConfigPath", "OK", "1 warning"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not mention %q:\n%s", want, out.String())
		}
	}
}

// A DNS file that does not exist yet is watched through its directory; only a
// missing directory leaves it unwatched, which must not stop the server.
func TestDNSWatchPath(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "dns.json")
	if err := os.WriteFile(existing, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write dns: %v", err)
	}
	for _, tc := range []struct {
		path, want string
		wantErr    bool
	}{
		{path: "", want: ""},
		{path: existing, want: existing},
		{path: filepath.Join(dir, "missing.json"), want: filepath.Join(dir, "missing.json")},
		{path: filepath.Join(dir, "missing-dir", "dns.json"), want: "", wantErr: true},
	} {
		got, err := dnsWatchPath(tc.path)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("dnsWatchPath(%q) = %q, %v; want %q, error %v", tc.path, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestStartupReportAddWarning(t *testing.T) {
	var report startupReport
	report.addWarning(categoryConfig, "XRAY_DNS_PATH", "DNS file is not watched")
	text := strings.Join(report.render(startupReportTitle, "", ""), "\n")
	if !strings.Contains(text, "[警告] [配置错误] XRAY_DNS_PATH: DNS file is not watched") {
		t.Errorf("summary does not show the warning:\n%s", text)
	}
}
