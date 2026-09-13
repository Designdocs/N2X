package conf

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodDNS = `{"servers": ["1.1.1.1"]}`

// watchEvents collects what Watch reports so tests can wait for it.
type watchEvents struct {
	reloaded chan struct{}
	rejected chan error
}

func newWatchEvents() *watchEvents {
	return &watchEvents{reloaded: make(chan struct{}, 8), rejected: make(chan error, 8)}
}

func (w *watchEvents) reload() {
	select {
	case w.reloaded <- struct{}{}:
	default:
	}
}

func (w *watchEvents) reject(err error) {
	select {
	case w.rejected <- err:
	default:
	}
}

func (w *watchEvents) wantReload(t *testing.T, why string) {
	t.Helper()
	select {
	case <-w.reloaded:
	case err := <-w.rejected:
		t.Fatalf("%s: reload rejected: %v", why, err)
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: reload did not fire", why)
	}
}

func (w *watchEvents) wantReject(t *testing.T, why string) error {
	t.Helper()
	select {
	case <-w.reloaded:
		t.Fatalf("%s: reload fired", why)
	case err := <-w.rejected:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: rejected was not called", why)
	}
	return nil
}

// watchedDNSConfig writes a valid config whose xray core uses dns, loads it
// as the running config and starts watching both files.
func watchedDNSConfig(t *testing.T, dns string) (*Conf, string, *watchEvents) {
	t.Helper()
	promptWatch(t)
	doc := validDoc()
	doc["Cores"] = []any{map[string]any{"Type": "xray", "DnsConfigPath": dns}}
	config := writeDoc(t, doc)
	c, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	events := newWatchEvents()
	stop, err := c.Watch(config, dns, ValidateOptions{}, events.reload, events.reject)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	t.Cleanup(stop)
	return c, config, events
}

// A DNS file that breaks while xray runs with it must not restart xray with
// its default DNS settings: the reload is rejected and names the DNS file.
func TestConf_WatchKeepsRunningDNSWhenTheFileBreaks(t *testing.T) {
	dns := filepath.Join(t.TempDir(), "dns.json")
	writeFile(t, dns, goodDNS)
	_, _, events := watchedDNSConfig(t, dns)

	writeFile(t, dns, `{"servers": [}`)
	err := events.wantReject(t, "broken DNS file")
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || len(validationErr.Issues) != 1 {
		t.Fatalf("rejected got %v, want a ValidationError with one issue", err)
	}
	issue := validationErr.Issues[0]
	if issue.Path != "Cores[0].DnsConfigPath" || issue.Kind != IssueSyntax {
		t.Errorf("issue = %+v, want a syntax issue at Cores[0].DnsConfigPath", issue)
	}
	if strings.Contains(issue.Message, "default DNS") || !strings.Contains(issue.Message, "current DNS") {
		t.Errorf("issue message does not say the running DNS is kept: %q", issue.Message)
	}

	writeFile(t, dns, `{"servers": ["8.8.8.8"]}`)
	events.wantReload(t, "fixed DNS file")
}

// When xray already runs without its DNS file, the DNS problem is not new
// and other edits still apply.
func TestConf_WatchAppliesEditsWhenDNSWasAlreadyBroken(t *testing.T) {
	dns := filepath.Join(t.TempDir(), "dns.json")
	writeFile(t, dns, `{"servers": [}`)
	c, config, events := watchedDNSConfig(t, dns)
	if len(c.Warnings) != 1 {
		t.Fatalf("running config warnings = %v, want the DNS warning", c.Warnings)
	}

	doc := validDoc()
	doc["Log"] = map[string]any{"Level": "debug"}
	doc["Cores"] = []any{map[string]any{"Type": "xray", "DnsConfigPath": dns}}
	writeFile(t, config, mustJSON(t, doc))
	events.wantReload(t, "config edit")
	if c.LogConfig.Level != "debug" {
		t.Errorf("edit not applied: Log.Level = %q", c.LogConfig.Level)
	}
}

// A DNS file that does not exist yet is created by xray once the panel sends
// DNS settings; that creation has to reach the watcher.
func TestConf_WatchPicksUpADNSFileCreatedLater(t *testing.T) {
	dir := t.TempDir()
	dns := filepath.Join(dir, "dns.json")
	_, _, events := watchedDNSConfig(t, dns)

	writeFile(t, filepath.Join(dir, "other.json"), `{}`)
	select {
	case <-events.reloaded:
		t.Fatal("a change to another file in the DNS directory fired a reload")
	case err := <-events.rejected:
		t.Fatalf("a change to another file in the DNS directory was handled: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	writeFile(t, dns, goodDNS)
	events.wantReload(t, "DNS file created")
}

func mustJSON(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return string(data)
}
