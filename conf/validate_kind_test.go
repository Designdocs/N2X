package conf

import (
	"path/filepath"
	"testing"
)

// issueKindAt returns the kind of the first issue at path.
func issueKindAt(t *testing.T, err error, path string) IssueKind {
	t.Helper()
	for _, issue := range validationIssues(t, err) {
		if issue.Path == path {
			return issue.Kind
		}
	}
	t.Fatalf("no issue at %s: %v", path, err)
	return IssueConfig
}

func TestIssueKindSeparatesSyntaxConfigAndCertificateProblems(t *testing.T) {
	t.Run("broken JSON is a syntax problem", func(t *testing.T) {
		path := writeConfigText(t, `{"Log": {"Level": "info"},, "Cores": []}`)
		_, err := LoadValidated(path, ValidateOptions{})
		issues := validationIssues(t, err)
		if len(issues) != 1 || issues[0].Kind != IssueSyntax {
			t.Fatalf("issues = %+v, want one syntax issue", issues)
		}
	})

	t.Run("duplicate key is a syntax problem", func(t *testing.T) {
		path := writeConfigText(t, `{"Log": {"Level": "info", "Level": "debug"}, "Cores": [{"Type": "xray"}], "Nodes": []}`)
		_, err := LoadValidated(path, ValidateOptions{})
		if kind := issueKindAt(t, err, "Log.Level"); kind != IssueSyntax {
			t.Errorf("kind = %v, want IssueSyntax", kind)
		}
	})

	t.Run("broken referenced JSON file is a syntax problem", func(t *testing.T) {
		doc := validDoc()
		route := filepath.Join(t.TempDir(), "route.json")
		writeFile(t, route, `{"rules": [}`)
		docCore(doc, 0)["RouteConfigPath"] = route
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		if kind := issueKindAt(t, err, "Cores[0].RouteConfigPath"); kind != IssueSyntax {
			t.Errorf("kind = %v, want IssueSyntax", kind)
		}
	})

	t.Run("unknown key is a config problem", func(t *testing.T) {
		doc := validDoc()
		docNode(doc, 0)["NodeTyp"] = "vless"
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		if kind := issueKindAt(t, err, "Nodes[0].NodeTyp"); kind != IssueConfig {
			t.Errorf("kind = %v, want IssueConfig", kind)
		}
	})

	t.Run("certificate settings are a certificate problem", func(t *testing.T) {
		doc := validDoc()
		docNode(doc, 0)["CertConfig"] = map[string]any{"CertMode": "bogus"}
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		if kind := issueKindAt(t, err, "Nodes[0].CertConfig"); kind != IssueCert {
			t.Errorf("kind = %v, want IssueCert", kind)
		}
	})
}
