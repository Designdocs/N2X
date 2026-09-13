package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/node"
	log "github.com/sirupsen/logrus"
)

func renderReport(r *startupReport) string {
	return strings.Join(r.render(startupReportTitle, "未启动任何核心和节点", "N2X check -c /etc/N2X/config.json"), "\n")
}

// lineIndex returns the index of the first line containing want, or -1.
func lineIndex(lines []string, want string) int {
	for i, line := range lines {
		if strings.Contains(line, want) {
			return i
		}
	}
	return -1
}

func TestStartupReportGroupsConfigIssuesByCategory(t *testing.T) {
	var report startupReport
	report.addConfigError(&conf.ValidationError{File: "/etc/N2X/config.json", Issues: []conf.Issue{
		{Path: "Nodes[1].CertConfig", Message: "unsupported CertMode \"bogus\"", Kind: conf.IssueCert},
		{Path: "Nodes[0].NodeTyp", Message: "unknown key", Kind: conf.IssueConfig},
		{Path: "Cores[0].RouteConfigPath", Message: "route.json: invalid JSON at line 3", Kind: conf.IssueSyntax},
	}})

	lines := report.render(startupReportTitle, "未启动任何核心和节点", "N2X check -c /etc/N2X/config.json")
	text := strings.Join(lines, "\n")
	syntax := lineIndex(lines, "[格式错误] Cores[0].RouteConfigPath: route.json: invalid JSON at line 3")
	config := lineIndex(lines, "[配置错误] Nodes[0].NodeTyp: unknown key")
	cert := lineIndex(lines, `[证书错误] Nodes[1].CertConfig: unsupported CertMode "bogus"`)
	if syntax < 0 || config < 0 || cert < 0 {
		t.Fatalf("summary misses a categorized line:\n%s", text)
	}
	if !(syntax < config && config < cert) {
		t.Errorf("categories out of order (want 格式, 配置, 证书):\n%s", text)
	}
	for _, want := range []string{"N2X 启动错误摘要", "共 3 项", "格式错误 1", "未启动任何核心和节点", "N2X check -c /etc/N2X/config.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary does not mention %q:\n%s", want, text)
		}
	}
}

func TestStartupReportKeepsPlainLoadErrors(t *testing.T) {
	var report startupReport
	report.addConfigError(fmt.Errorf("open config file error: %w", os.ErrNotExist))
	if text := renderReport(&report); !strings.Contains(text, "[配置错误] open config file error") {
		t.Fatalf("plain load error missing:\n%s", text)
	}
}

func TestStartupReportNamesFailedNodes(t *testing.T) {
	nodes := []conf.NodeConfig{
		{ApiConfig: conf.ApiConfig{NodeType: "vless", NodeID: 1}},
		{ApiConfig: conf.ApiConfig{NodeType: "anytls", NodeID: 2}},
		{ApiConfig: conf.ApiConfig{NodeType: "trojan", NodeID: 3}},
	}
	var report startupReport
	report.addNodeFailures(nodes, []node.StartFailure{
		{Index: 2, Stage: node.StageCore, Err: errors.New("add new node error: inbound build failed")},
		{Index: 1, Stage: node.StageCert, Err: errors.New("request cert error: DNS self-test failed")},
		{Index: 0, Stage: node.StagePanel, Err: errors.New("get node info error: 404")},
	})

	lines := report.render(startupReportTitle, "1 个节点已启动", "")
	text := strings.Join(lines, "\n")
	cert := lineIndex(lines, "[证书错误] Nodes[1] (anytls #2): request cert error: DNS self-test failed")
	panelLine := lineIndex(lines, "[面板错误] Nodes[0] (vless #1): get node info error: 404")
	core := lineIndex(lines, "[生成错误] Nodes[2] (trojan #3): add new node error: inbound build failed")
	if cert < 0 || panelLine < 0 || core < 0 {
		t.Fatalf("summary misses a node line:\n%s", text)
	}
	if !(cert < panelLine && panelLine < core) {
		t.Errorf("categories out of order (want 证书, 面板, 生成):\n%s", text)
	}
	if strings.Contains(text, "排查") {
		t.Errorf("an empty hint must not print a hint line:\n%s", text)
	}
}

func TestStartupReportShortensLongMessages(t *testing.T) {
	var report startupReport
	report.add(categoryCore, "", "line one\nline two "+strings.Repeat("x", 2*maxProblemMessageRunes))
	lines := report.render(startupReportTitle, "", "")
	line := lines[lineIndex(lines, "[生成错误]")]
	if strings.Contains(line, "\n") || !strings.Contains(line, "line one line two") {
		t.Errorf("message was not flattened to one line: %q", line)
	}
	if !strings.HasSuffix(line, "…") || len([]rune(line)) > maxProblemMessageRunes+len([]rune("[生成错误] "))+1 {
		t.Errorf("message was not shortened: %d runes", len([]rune(line)))
	}
}

func TestStartupReportPublish(t *testing.T) {
	newLogger := func(out io.Writer) *log.Logger {
		logger := log.New()
		logger.SetOutput(out)
		logger.SetFormatter(&log.TextFormatter{DisableTimestamp: true})
		return logger
	}
	var report startupReport
	report.add(categoryConfig, "Log.Output", "directory /missing does not exist")

	t.Run("logger writing to stderr prints once", func(t *testing.T) {
		var stderr bytes.Buffer
		report.publish(&stderr, newLogger(&stderr), startupReportTitle, "", "")
		if got := strings.Count(stderr.String(), "[配置错误] Log.Output"); got != 1 {
			t.Errorf("summary printed %d times, want once:\n%s", got, stderr.String())
		}
	})

	t.Run("logger writing to a file gets a copy", func(t *testing.T) {
		var stderr, logFile bytes.Buffer
		report.publish(&stderr, newLogger(&logFile), startupReportTitle, "", "")
		for name, out := range map[string]string{"stderr": stderr.String(), "log file": logFile.String()} {
			if !strings.Contains(out, "[配置错误] Log.Output") {
				t.Errorf("%s misses the summary:\n%s", name, out)
			}
		}
	})

	t.Run("empty report prints nothing", func(t *testing.T) {
		var stderr bytes.Buffer
		var empty startupReport
		empty.publish(&stderr, newLogger(&stderr), startupReportTitle, "", "")
		if stderr.Len() != 0 {
			t.Errorf("empty report printed:\n%s", stderr.String())
		}
	})
}

// The summary has to reach the terminal or journald when the server refuses
// to start, and point at the check command.
func TestServerPrintsSummaryForInvalidConfig(t *testing.T) {
	if os.Getenv(runExitProbeEnvironment) == "1" {
		os.Args = []string{"N2X", "server", "-c", os.Getenv(probeConfigEnvironment)}
		Run()
		return
	}
	config := writeTestConfig(t, invalidTestConfig)
	t.Setenv(probeConfigEnvironment, config)
	code, output := runExitProbeOutput(t, "TestServerPrintsSummaryForInvalidConfig")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, want := range []string{"N2X 启动错误摘要", "[配置错误] Nodes[0].NodeTyp", "N2X check -c " + config} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not mention %q", want)
		}
	}
}

func TestStartupReportRedactsPanelToken(t *testing.T) {
	var report startupReport
	report.add(categoryPanel, "Nodes[0] (vless #3)",
		`get node info error: Get "http://127.0.0.1:1/config?node_id=3&token=s3cr3t-key&node_type=vless": refused`)
	text := renderReport(&report)
	if strings.Contains(text, "s3cr3t-key") {
		t.Fatalf("summary leaks the panel token:\n%s", text)
	}
	if !strings.Contains(text, "token=[REDACTED]&node_type=vless") {
		t.Errorf("token was not replaced in place:\n%s", text)
	}
}

func TestNodesOutcome(t *testing.T) {
	tests := []struct {
		failed, total int
		want, reject  string
	}{
		{0, 2, "核心与节点均已启动", "失败"},
		{1, 3, "1/3 个节点启动失败，其余节点正常运行", ""},
		{2, 2, "全部 2 个节点启动失败", "其余节点"},
	}
	for _, tt := range tests {
		got := nodesOutcome(tt.failed, tt.total)
		if !strings.Contains(got, tt.want) || (tt.reject != "" && strings.Contains(got, tt.reject)) {
			t.Errorf("nodesOutcome(%d, %d) = %q, want %q without %q", tt.failed, tt.total, got, tt.want, tt.reject)
		}
	}
}
