package conf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validDoc returns the smallest config that passes validation: one core and
// one node, as a mutable document so each case can break exactly one thing.
func validDoc() map[string]any {
	return map[string]any{
		"Log":   map[string]any{"Level": "info", "Output": ""},
		"Cores": []any{map[string]any{"Type": "xray"}},
		"Nodes": []any{validNode(1)},
	}
}

func validNode(id int) map[string]any {
	return map[string]any{
		"Core":     "xray",
		"ApiHost":  "https://panel.example.com",
		"ApiKey":   "secret",
		"NodeID":   id,
		"NodeType": "vless",
	}
}

func docNode(doc map[string]any, i int) map[string]any {
	return doc["Nodes"].([]any)[i].(map[string]any)
}

func docCore(doc map[string]any, i int) map[string]any {
	return doc["Cores"].([]any)[i].(map[string]any)
}

func writeDoc(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return writeConfigText(t, string(data))
}

func writeConfigText(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, text)
	return path
}

func validationIssues(t *testing.T, err error) []Issue {
	t.Helper()
	if err == nil {
		t.Fatal("expected the config to be rejected")
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	return validationErr.Issues
}

// assertIssue fails unless some issue sits at path and mentions every want.
func assertIssue(t *testing.T, err error, path string, wants ...string) {
	t.Helper()
	issues := validationIssues(t, err)
	for _, issue := range issues {
		if issue.Path != path {
			continue
		}
		matched := true
		for _, want := range wants {
			if !strings.Contains(issue.Message, want) {
				matched = false
				break
			}
		}
		if matched {
			return
		}
	}
	t.Fatalf("no issue at %q mentioning %q; got:\n%v", path, wants, err)
}

func TestLoadValidatedAcceptsMinimalConfig(t *testing.T) {
	c, err := LoadValidated(writeDoc(t, validDoc()), ValidateOptions{})
	if err != nil {
		t.Fatalf("expected a valid config, got %v", err)
	}
	if len(c.NodeConfig) != 1 || c.NodeConfig[0].ApiConfig.NodeID != 1 {
		t.Fatalf("config was not decoded: %+v", c.NodeConfig)
	}
}

// The shipped example is what operators copy, so it must pass as-is once its
// absolute /etc/N2X paths point at files that exist.
func TestLoadValidatedAcceptsExampleConfig(t *testing.T) {
	t.Setenv("N2X_API_HOST", "https://panel.example.com")
	t.Setenv("N2X_API_KEY", "test-key")

	dir := t.TempDir()
	for _, name := range []string{"dns.json", "route.json", "custom_outbound.json"} {
		data, err := os.ReadFile(filepath.Join("..", "example", name))
		if err != nil {
			t.Fatalf("read example %s: %v", name, err)
		}
		writeFile(t, filepath.Join(dir, name), string(data))
	}
	example, err := os.ReadFile("../example/config.json")
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	text := strings.ReplaceAll(string(example), "/etc/N2X/", dir+"/")
	path := writeConfigText(t, text)

	c, err := LoadValidated(path, ValidateOptions{CoreTypes: []string{"xray", "sing"}})
	if err != nil {
		// File-mode certificates are the only thing left to create.
		for _, issue := range validationIssues(t, err) {
			if !strings.Contains(issue.Message, "certificate file not found") {
				t.Fatalf("example config rejected: %v", err)
			}
		}
		for _, node := range mustLoad(t, path).NodeConfig {
			cert := node.Options.CertConfig
			if cert != nil && cert.CertMode == "file" {
				writeFile(t, cert.CertFile, "cert")
				writeFile(t, cert.KeyFile, "key")
			}
		}
		if c, err = LoadValidated(path, ValidateOptions{CoreTypes: []string{"xray", "sing"}}); err != nil {
			t.Fatalf("example config rejected: %v", err)
		}
	}
	if len(c.NodeConfig) == 0 || len(c.CoresConfig) != 2 {
		t.Fatalf("example config decoded wrongly: %d nodes, %d cores", len(c.NodeConfig), len(c.CoresConfig))
	}
}

func mustLoad(t *testing.T, path string) *Conf {
	t.Helper()
	c := New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return c
}

func TestLoadValidatedReportsSyntaxErrorLocation(t *testing.T) {
	text := "{\n  // comments are allowed\n  \"Log\": {\"Level\": \"info\"},\n  \"Cores\": [ }\n}\n"
	_, err := LoadValidated(writeConfigText(t, text), ValidateOptions{})
	issues := validationIssues(t, err)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "line 4") {
		t.Fatalf("expected one syntax issue on line 4, got %v", err)
	}
}

// Block comments are blanked out before parsing; the reported line must still
// match the file the operator is looking at.
func TestLoadValidatedSyntaxLineCountsBlockComments(t *testing.T) {
	text := "{\n/* one\ntwo\nthree */\n\"Log\": {\"Level\": \"info\"\n}\n"
	_, err := LoadValidated(writeConfigText(t, text), ValidateOptions{})
	issues := validationIssues(t, err)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "line 7") {
		t.Fatalf("expected the syntax issue on line 7, got %v", err)
	}
}

func TestLoadValidatedAcceptsTrailingCommasAndComments(t *testing.T) {
	text := `{
  "Log": {"Level": "info",}, // trailing comma
  "Cores": [{"Type": "xray"},],
  "Nodes": [{"Core": "xray", "ApiHost": "https://p.example.com", "ApiKey": "k", "NodeID": 1, "NodeType": "vless",}],
}`
	if _, err := LoadValidated(writeConfigText(t, text), ValidateOptions{}); err != nil {
		t.Fatalf("expected json5 niceties to be accepted, got %v", err)
	}
}

func TestLoadValidatedRejectsDuplicateKeys(t *testing.T) {
	t.Run("top level", func(t *testing.T) {
		text := `{"Log": {"Level": "info"}, "Log": {"Level": "debug"}, "Cores": [], "Nodes": []}`
		_, err := LoadValidated(writeConfigText(t, text), ValidateOptions{})
		assertIssue(t, err, "Log", "duplicate key")
	})
	t.Run("inside a node", func(t *testing.T) {
		text := `{"Cores": [{"Type": "xray"}], "Nodes": [{"NodeID": 1, "NodeID": 2}]}`
		_, err := LoadValidated(writeConfigText(t, text), ValidateOptions{})
		assertIssue(t, err, "Nodes[0].NodeID", "duplicate key")
	})
	t.Run("differing only in case", func(t *testing.T) {
		doc := validDoc()
		docNode(doc, 0)["nodeid"] = 2
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		assertIssue(t, err, "Nodes[0].nodeid", "duplicate", "NodeID")
	})
}

func TestLoadValidatedRejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		path   string
		wants  []string
	}{
		{"top level typo", func(d map[string]any) { d["Node"] = []any{} }, "Node", []string{"unknown key", `"Nodes"`}},
		{"log field is case sensitive", func(d map[string]any) {
			d["Log"] = map[string]any{"level": "debug"}
		}, "Log.level", []string{"unknown key", `"Level"`}},
		{"node typo", func(d map[string]any) { docNode(d, 0)["CertConfg"] = map[string]any{} }, "Nodes[0].CertConfg", []string{`"CertConfig"`}},
		{"cert typo", func(d map[string]any) {
			docNode(d, 0)["CertConfig"] = map[string]any{"CertMode": "none", "CertDomian": "a.example.com"}
		}, "Nodes[0].CertConfig.CertDomian", []string{`"CertDomain"`}},
		{"xray option on a sing node", func(d map[string]any) {
			d["Cores"] = []any{map[string]any{"Type": "sing"}}
			docNode(d, 0)["Core"] = "sing"
			docNode(d, 0)["DNSType"] = "UseIPv4"
		}, "Nodes[0].DNSType", []string{"unknown key"}},
		{"sing core key on xray core", func(d map[string]any) {
			docCore(d, 0)["OriginalPath"] = "/tmp/sing.json"
		}, "Cores[0].OriginalPath", []string{"unknown key"}},
		{"nested limit field", func(d map[string]any) {
			docNode(d, 0)["LimitConfig"] = map[string]any{"SpeedLimt": 10}
		}, "Nodes[0].LimitConfig.SpeedLimt", []string{`"SpeedLimit"`}},
		{"api key flat when ApiConfig block exists", func(d map[string]any) {
			node := docNode(d, 0)
			node["ApiConfig"] = map[string]any{"ApiHost": "https://p.example.com", "ApiKey": "k", "NodeID": 1, "NodeType": "vless"}
		}, "Nodes[0].ApiHost", []string{"unknown key"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			tt.mutate(doc)
			_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			assertIssue(t, err, tt.path, tt.wants...)
		})
	}
}

func TestLoadValidatedAllowsUnderscoreKeysAndCaseInsensitiveNodeKeys(t *testing.T) {
	doc := validDoc()
	doc["_help"] = map[string]any{"Nodes": "anything"}
	node := docNode(doc, 0)
	node["_note"] = "kept for humans"
	delete(node, "NodeType")
	node["nodetype"] = "vless"
	node["CertConfig"] = map[string]any{"cert_mode": "none", "_comment": "x"}
	if _, err := LoadValidated(writeDoc(t, doc), ValidateOptions{}); err != nil {
		t.Fatalf("expected config to be accepted, got %v", err)
	}
}

func TestLoadValidatedChecksEnvPlaceholders(t *testing.T) {
	t.Setenv("N2X_TEST_SET_KEY", "from-env")

	doc := validDoc()
	docNode(doc, 0)["ApiKey"] = "${N2X_TEST_UNSET_KEY}"
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].ApiKey", "N2X_TEST_UNSET_KEY")

	doc = validDoc()
	docNode(doc, 0)["ApiKey"] = "${N2X_TEST_SET_KEY}"
	docNode(doc, 0)["ApiHost"] = "${N2X_TEST_UNSET_HOST:-https://panel.example.com}"
	c, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	if err != nil {
		t.Fatalf("expected env placeholders to resolve, got %v", err)
	}
	if got := c.NodeConfig[0].ApiConfig.Key; got != "from-env" {
		t.Fatalf("ApiKey = %q, want from-env", got)
	}
}

func TestLoadValidatedReportsTypeMismatch(t *testing.T) {
	doc := validDoc()
	docNode(doc, 0)["NodeID"] = "1"
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	issues := validationIssues(t, err)
	if !strings.Contains(err.Error(), "NodeID") {
		t.Fatalf("expected the type error to name NodeID, got %v", issues)
	}
}

func TestLoadValidatedRejectsBadValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		path   string
		wants  []string
	}{
		{"log level", func(d map[string]any) { d["Log"] = map[string]any{"Level": "verbose"} }, "Log.Level", []string{"verbose"}},
		{"log output directory", func(d map[string]any) {
			d["Log"] = map[string]any{"Level": "info", "Output": "/nonexistent-n2x-dir/n2x.log"}
		}, "Log.Output", []string{"directory"}},
		{"no cores", func(d map[string]any) { d["Cores"] = []any{} }, "Cores", []string{"at least one"}},
		{"no nodes", func(d map[string]any) { d["Nodes"] = []any{} }, "Nodes", []string{"at least one"}},
		{"unknown core type", func(d map[string]any) { docCore(d, 0)["Type"] = "v2ray" }, "Cores[0].Type", []string{"v2ray"}},
		{"core type case", func(d map[string]any) { docCore(d, 0)["Type"] = "Xray" }, "Cores[0].Type", []string{`"xray"`}},
		{"duplicate core names", func(d map[string]any) {
			d["Cores"] = []any{map[string]any{"Type": "xray"}, map[string]any{"Type": "xray"}}
		}, "Cores[1]", []string{"Name"}},
		{"xray log level", func(d map[string]any) {
			docCore(d, 0)["Log"] = map[string]any{"Level": "warn"}
		}, "Cores[0].Log.Level", []string{"warn"}},
		{"xray route file missing", func(d map[string]any) {
			docCore(d, 0)["RouteConfigPath"] = "/nonexistent-n2x/route.json"
		}, "Cores[0].RouteConfigPath", []string{"route.json"}},
		{"sing log level", func(d map[string]any) {
			d["Cores"] = []any{map[string]any{"Type": "sing", "Log": map[string]any{"Level": "verbose"}}}
			docNode(d, 0)["Core"] = "sing"
		}, "Cores[0].Log.Level", []string{"verbose"}},
		{"sing original path missing", func(d map[string]any) {
			d["Cores"] = []any{map[string]any{"Type": "sing", "OriginalPath": "/nonexistent-n2x/sing.json"}}
			docNode(d, 0)["Core"] = "sing"
		}, "Cores[0].OriginalPath", []string{"sing.json"}},
		{"api host without scheme", func(d map[string]any) { docNode(d, 0)["ApiHost"] = "panel.example.com" }, "Nodes[0].ApiHost", []string{"http"}},
		{"empty api key", func(d map[string]any) { docNode(d, 0)["ApiKey"] = "" }, "Nodes[0].ApiKey", []string{"required"}},
		{"node id", func(d map[string]any) { docNode(d, 0)["NodeID"] = 0 }, "Nodes[0].NodeID", []string{"positive"}},
		{"node type", func(d map[string]any) { docNode(d, 0)["NodeType"] = "vlesss" }, "Nodes[0].NodeType", []string{"vlesss"}},
		{"negative timeout", func(d map[string]any) { docNode(d, 0)["Timeout"] = -1 }, "Nodes[0].Timeout", []string{"negative"}},
		{"api send ip", func(d map[string]any) { docNode(d, 0)["ApiSendIP"] = "1.2.3" }, "Nodes[0].ApiSendIP", []string{"IP"}},
		{"websocket url", func(d map[string]any) {
			docNode(d, 0)["WebSocket"] = map[string]any{"Enabled": true, "URL": "https://panel.example.com/ws/"}
		}, "Nodes[0].WebSocket.URL", []string{"ws://"}},
		{"core case", func(d map[string]any) { docNode(d, 0)["Core"] = "Xray" }, "Nodes[0].Core", []string{`"xray"`}},
		{"core not configured", func(d map[string]any) { docNode(d, 0)["Core"] = "sing" }, "Nodes[0].Core", []string{"sing"}},
		{"core name unknown", func(d map[string]any) { docNode(d, 0)["CoreName"] = "xray-2" }, "Nodes[0].CoreName", []string{"xray-2"}},
		{"listen ip with port", func(d map[string]any) { docNode(d, 0)["ListenIP"] = "0.0.0.0:443" }, "Nodes[0].ListenIP", []string{"0.0.0.0:443"}},
		{"send ip", func(d map[string]any) { docNode(d, 0)["SendIP"] = "localhost" }, "Nodes[0].SendIP", []string{"localhost"}},
		{"negative traffic", func(d map[string]any) { docNode(d, 0)["ReportMinTraffic"] = -1 }, "Nodes[0].ReportMinTraffic", []string{"negative"}},
		{"negative speed limit", func(d map[string]any) {
			docNode(d, 0)["LimitConfig"] = map[string]any{"SpeedLimit": -5}
		}, "Nodes[0].LimitConfig.SpeedLimit", []string{"negative"}},
		{"dynamic limit without config", func(d map[string]any) {
			docNode(d, 0)["LimitConfig"] = map[string]any{"EnableDynamicSpeedLimit": true}
		}, "Nodes[0].LimitConfig.DynamicSpeedLimitConfig", []string{"required"}},
		{"xray dns type", func(d map[string]any) { docNode(d, 0)["DNSType"] = "UseIPv5" }, "Nodes[0].DNSType", []string{"UseIPv5"}},
		{"xray fallback without dest", func(d map[string]any) {
			docNode(d, 0)["FallBackConfigs"] = []any{map[string]any{"SNI": "a.example.com"}}
		}, "Nodes[0].FallBackConfigs[0].Dest", []string{"required"}},
		{"xray proxy protocol version", func(d map[string]any) {
			docNode(d, 0)["FallBackConfigs"] = []any{map[string]any{"Dest": "80", "ProxyProtocolVer": 3}}
		}, "Nodes[0].FallBackConfigs[0].ProxyProtocolVer", []string{"0, 1 or 2"}},
		{"artx share", func(d map[string]any) {
			docNode(d, 0)["ArtXOptions"] = map[string]any{"WindowBudgetSharePercent": 150}
		}, "Nodes[0].ArtXOptions.WindowBudgetSharePercent", []string{"100"}},
		{"artx reserve", func(d map[string]any) {
			docNode(d, 0)["ArtXOptions"] = map[string]any{"WindowBudgetReservePercent": 100}
		}, "Nodes[0].ArtXOptions.WindowBudgetReservePercent", []string{"99"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			tt.mutate(doc)
			_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			assertIssue(t, err, tt.path, tt.wants...)
		})
	}
}

func singDoc(node map[string]any) map[string]any {
	doc := validDoc()
	doc["Cores"] = []any{map[string]any{"Type": "sing"}}
	merged := validNode(1)
	merged["Core"] = "sing"
	for key, value := range node {
		merged[key] = value
	}
	doc["Nodes"] = []any{merged}
	return doc
}

func TestLoadValidatedRejectsBadSingOptions(t *testing.T) {
	tests := []struct {
		name  string
		node  map[string]any
		path  string
		wants []string
	}{
		{"domain strategy", map[string]any{"DomainStrategy": "prefer_ipv5"}, "Nodes[0].DomainStrategy", []string{"prefer_ipv5"}},
		{"shadowtls version", map[string]any{"ShadowTLSOptions": map[string]any{"Version": 4}}, "Nodes[0].ShadowTLSOptions.Version", []string{"4"}},
		{"shadowtls wildcard sni", map[string]any{"ShadowTLSOptions": map[string]any{"WildcardSNI": "some"}}, "Nodes[0].ShadowTLSOptions.WildcardSNI", []string{"some"}},
		{"naive network", map[string]any{"NaiveOptions": map[string]any{"Network": "quic"}}, "Nodes[0].NaiveOptions.Network", []string{"quic"}},
		{"tuic heartbeat", map[string]any{"TuicOptions": map[string]any{"Heartbeat": "10"}}, "Nodes[0].TuicOptions.Heartbeat", []string{"duration"}},
		{"tuic congestion control", map[string]any{"TuicOptions": map[string]any{"CongestionControl": "reno"}}, "Nodes[0].TuicOptions.CongestionControl", []string{"reno"}},
		{"port hopping", map[string]any{"HysteriaOptions": map[string]any{"PortHopping": []any{"30000-20000x"}}}, "Nodes[0].HysteriaOptions.PortHopping", nil},
		{"masquerade scheme", map[string]any{"HysteriaOptions": map[string]any{"Masquerade": "ftp://files.example.com"}}, "Nodes[0].HysteriaOptions.Masquerade", []string{"ftp"}},
		{"fallback port", map[string]any{"FallBackConfigs": map[string]any{"FallBack": map[string]any{"Server": "127.0.0.1", "ServerPort": "http"}}}, "Nodes[0].FallBackConfigs.FallBack.ServerPort", []string{"http"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadValidated(writeDoc(t, singDoc(tt.node)), ValidateOptions{})
			assertIssue(t, err, tt.path, tt.wants...)
		})
	}
}

// A node without Core is decoded lazily once a core is chosen, so its
// core-specific options have to be checked for both cores.
func TestLoadValidatedChecksOptionsOfUnpinnedNodes(t *testing.T) {
	doc := validDoc()
	doc["Cores"] = []any{map[string]any{"Type": "xray"}, map[string]any{"Type": "sing"}}
	delete(docNode(doc, 0), "Core")
	docNode(doc, 0)["DomainStrategy"] = "prefer_ipv5"
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].DomainStrategy", "prefer_ipv5")
}

// An unpinned node only ever runs on a configured core, so options that
// belong to a core type the file does not configure are never read and must
// not stop the server.
func TestLoadValidatedIgnoresOptionsOfCoresNotConfigured(t *testing.T) {
	cases := map[string]func(doc map[string]any){
		"sing option with only xray": func(doc map[string]any) {
			delete(docNode(doc, 0), "Core")
			docNode(doc, 0)["DomainStrategy"] = "prefer_ipv5"
		},
		"xray option with only sing": func(doc map[string]any) {
			doc["Cores"] = []any{map[string]any{"Type": "sing"}}
			delete(docNode(doc, 0), "Core")
			docNode(doc, 0)["DNSType"] = "UseIPv5"
		},
		"sing option on a node pinned to xray by CoreName": func(doc map[string]any) {
			doc["Cores"] = []any{
				map[string]any{"Type": "xray", "Name": "x"},
				map[string]any{"Type": "sing", "Name": "s"},
			}
			delete(docNode(doc, 0), "Core")
			docNode(doc, 0)["CoreName"] = "x"
			docNode(doc, 0)["DomainStrategy"] = "prefer_ipv5"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			mutate(doc)
			if _, err := LoadValidated(writeDoc(t, doc), ValidateOptions{}); err != nil {
				t.Fatalf("expected the config to pass, got %v", err)
			}
		})
	}
}

// Values above 2^53 must survive validation unchanged instead of being
// rounded through float64.
func TestLoadValidatedKeepsLargeIntegers(t *testing.T) {
	const large = 9007199254740993
	text := strings.Replace(mustMarshal(t, validDoc()), `"NodeID":1`, `"NodeID":1,"LimitConfig":{"SpeedLimit":9007199254740993}`, 1)
	c, err := LoadValidated(writeConfigText(t, text), ValidateOptions{})
	if err != nil {
		t.Fatalf("expected a valid config, got %v", err)
	}
	if got := c.NodeConfig[0].Options.LimitConfig.SpeedLimit; got != large {
		t.Fatalf("SpeedLimit = %d, want %d", got, large)
	}
}

func mustMarshal(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return string(data)
}

func TestLoadValidatedRestrictsCoreTypesToTheBinary(t *testing.T) {
	doc := validDoc()
	doc["Cores"] = []any{map[string]any{"Type": "sing"}}
	docNode(doc, 0)["Core"] = "sing"
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{CoreTypes: []string{"xray"}})
	assertIssue(t, err, "Cores[0].Type", "not built into this binary")
}

func TestLoadValidatedChecksXrayConfigFiles(t *testing.T) {
	dir := t.TempDir()
	badJSON := filepath.Join(dir, "route.json")
	writeFile(t, badJSON, `{"rules": [}`)
	objectInbound := filepath.Join(dir, "inbound.json")
	writeFile(t, objectInbound, `{"tag": "in"}`)

	doc := validDoc()
	core := docCore(doc, 0)
	core["RouteConfigPath"] = badJSON
	core["InboundConfigPath"] = objectInbound
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Cores[0].RouteConfigPath", "line 1")
	assertIssue(t, err, "Cores[0].InboundConfigPath", "array")
}

func TestLoadValidatedChecksCertConfig(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "a.cer")
	keyFile := filepath.Join(dir, "a.key")
	writeFile(t, certFile, "cert")
	writeFile(t, keyFile, "key")

	tests := []struct {
		name  string
		cert  map[string]any
		wants []string
	}{
		{"mode case", map[string]any{"CertMode": "DNS"}, []string{`"dns"`}},
		{"unknown mode", map[string]any{"CertMode": "acme"}, []string{"acme"}},
		{"file mode without paths", map[string]any{"CertMode": "file"}, []string{"CertFile"}},
		{"file mode missing file", map[string]any{"CertMode": "file", "CertFile": filepath.Join(dir, "missing.cer"), "KeyFile": keyFile}, []string{"certificate file not found", "missing.cer"}},
		{"dns without provider", map[string]any{"CertMode": "dns", "CertDomain": "a.example.com", "CertFile": certFile, "KeyFile": keyFile}, []string{"provider"}},
		{"http with wildcard", map[string]any{"CertMode": "http", "CertDomain": "*.example.com", "CertFile": certFile, "KeyFile": keyFile}, []string{"wildcard"}},
		{"domain placeholder without domain", map[string]any{"CertMode": "self", "CertFile": dir + "/{domain}.cer", "KeyFile": dir + "/{domain}.key"}, []string{"{domain}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			docNode(doc, 0)["CertConfig"] = tt.cert
			_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			assertIssue(t, err, "Nodes[0].CertConfig", tt.wants...)
		})
	}

	t.Run("valid dns config", func(t *testing.T) {
		doc := validDoc()
		docNode(doc, 0)["CertConfig"] = map[string]any{
			"CertMode": "dns", "CertDomain": "a.example.com", "Provider": "cloudflare",
			"Email": "ops@example.com", "DNSEnv": map[string]any{"CF_DNS_API_TOKEN": "token-value"},
		}
		if _, err := LoadValidated(writeDoc(t, doc), ValidateOptions{}); err != nil {
			t.Fatalf("expected valid dns cert config, got %v", err)
		}
	})
}

func TestLoadValidatedChecksAcrossNodes(t *testing.T) {
	t.Run("same panel node twice", func(t *testing.T) {
		doc := validDoc()
		doc["Nodes"] = []any{validNode(7), validNode(7)}
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		assertIssue(t, err, "Nodes[1]", "Nodes[0]")
	})
	t.Run("one certificate file for two domains", func(t *testing.T) {
		dir := t.TempDir()
		doc := validDoc()
		first, second := validNode(1), validNode(2)
		first["CertConfig"] = map[string]any{"CertMode": "self", "CertDomain": "a.example.com", "CertFile": dir + "/shared.cer", "KeyFile": dir + "/a.key"}
		second["CertConfig"] = map[string]any{"CertMode": "self", "CertDomain": "b.example.com", "CertFile": dir + "/shared.cer", "KeyFile": dir + "/b.key"}
		doc["Nodes"] = []any{first, second}
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		assertIssue(t, err, "Nodes[1].CertConfig.CertFile", "Nodes[0]")
	})
}

func TestLoadValidatedReportsEveryIssueAtOnce(t *testing.T) {
	doc := validDoc()
	doc["Log"] = map[string]any{"Level": "verbose"}
	docNode(doc, 0)["NodeType"] = "vlesss"
	docNode(doc, 0)["CertConfg"] = map[string]any{}
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	if issues := validationIssues(t, err); len(issues) < 3 {
		t.Fatalf("expected all three problems, got %v", err)
	}
}

func TestLoadValidatedChecksIncludedNodeFiles(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "node.json")
	node := validNode(1)
	node["EnableTFOO"] = true
	data, _ := json.Marshal(node)
	writeFile(t, included, string(data))

	doc := validDoc()
	doc["Nodes"] = []any{map[string]any{"Include": included}}
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].EnableTFOO", "unknown key")

	doc["Nodes"] = []any{map[string]any{"Include": filepath.Join(dir, "missing.json")}}
	_, err = LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].Include", "missing.json")
}

func TestLoadValidatedRejectsMissingFile(t *testing.T) {
	if _, err := LoadValidated(filepath.Join(t.TempDir(), "nope.json"), ValidateOptions{}); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}
