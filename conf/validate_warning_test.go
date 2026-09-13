package conf

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// withDNSFile returns a valid doc whose xray core reads its DNS settings from
// a file holding content, or from a missing file when content is empty.
func withDNSFile(t *testing.T, content string) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dns.json")
	if content != "" {
		writeFile(t, path, content)
	}
	doc := validDoc()
	docCore(doc, 0)["DnsConfigPath"] = path
	return doc
}

// A broken DNS file only costs xray its DNS settings, so it must not stop the
// server from starting or a reload from applying.
func TestLoadValidatedDowngradesDNSFileProblemsToWarnings(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantKind IssueKind
		want     string
	}{
		{name: "invalid JSON", content: `{"servers": [}`, wantKind: IssueSyntax, want: "line 1"},
		{name: "duplicate key", content: `{"servers": [], "servers": []}`, wantKind: IssueSyntax, want: "duplicate"},
		{name: "missing file", wantKind: IssueConfig, want: "cannot read"},
		{name: "not an object", content: `[]`, wantKind: IssueConfig, want: "JSON object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadValidated(writeDoc(t, withDNSFile(t, tt.content)), ValidateOptions{})
			if err != nil {
				t.Fatalf("config rejected for a DNS file problem: %v", err)
			}
			if len(c.Warnings) != 1 {
				t.Fatalf("warnings = %+v, want exactly one", c.Warnings)
			}
			warning := c.Warnings[0]
			if warning.Path != "Cores[0].DnsConfigPath" || warning.Kind != tt.wantKind || !strings.Contains(warning.Message, tt.want) {
				t.Errorf("warning = %+v, want Cores[0].DnsConfigPath kind %v mentioning %q", warning, tt.wantKind, tt.want)
			}
			if !strings.Contains(warning.Message, "default DNS") {
				t.Errorf("warning %q does not say what xray does instead", warning.Message)
			}
		})
	}
}

func TestLoadValidatedHasNoWarningsForAGoodDNSFile(t *testing.T) {
	c, err := LoadValidated(writeDoc(t, withDNSFile(t, `{"servers": ["1.1.1.1"]}`)), ValidateOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings = %+v, want none", c.Warnings)
	}
}

// Warnings found alongside real problems are still reported, apart from them.
func TestValidationErrorCarriesWarningsSeparately(t *testing.T) {
	doc := withDNSFile(t, `{"servers": [}`)
	docNode(doc, 0)["NodeTyp"] = "vless"
	_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("err = %v, want *ValidationError", err)
	}
	for _, issue := range validationErr.Issues {
		if issue.Path == "Cores[0].DnsConfigPath" {
			t.Errorf("DNS file problem counted as an error: %+v", issue)
		}
	}
	if len(validationErr.Warnings) != 1 || validationErr.Warnings[0].Path != "Cores[0].DnsConfigPath" {
		t.Errorf("warnings = %+v, want the DNS file problem", validationErr.Warnings)
	}
	if text := err.Error(); !strings.Contains(text, "warning") || !strings.Contains(text, "Cores[0].DnsConfigPath") {
		t.Errorf("error text does not list the warning:\n%s", text)
	}
}
