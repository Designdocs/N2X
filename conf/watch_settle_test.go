package conf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func watchedDNSWithTiming(t *testing.T, debounce, settle time.Duration) (string, *watchEvents) {
	t.Helper()
	promptWatch(t)
	watchDebounce, watchSettle = debounce, settle
	dns := filepath.Join(t.TempDir(), "dns.json")
	writeFile(t, dns, goodDNS)
	doc := validDoc()
	doc["Cores"] = []any{map[string]any{"Type": "xray", "DnsConfigPath": dns}}
	config := writeDoc(t, doc)
	running, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	events := newWatchEvents()
	stop, err := running.Watch(config, dns, ValidateOptions{}, events.reload, events.reject)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return dns, events
}

// A correction must be retained even when it follows a rejected edit inside
// the cooldown. The previous leading-edge throttle dropped the final edit.
func TestWatchAppliesCorrectionDuringCooldown(t *testing.T) {
	dns, events := watchedDNSWithTiming(t, 200*time.Millisecond, 20*time.Millisecond)
	writeFile(t, dns, `{"servers":[}`)
	events.wantReject(t, "invalid DNS")
	writeFile(t, dns, goodDNS)
	events.wantReload(t, "correction inside cooldown")
}

// Several writes can belong to one editor save. Only the completed document
// may reach validation, even if the whole save outlasts one settle interval.
func TestWatchWaitsForQuietAfterLastWrite(t *testing.T) {
	dns, events := watchedDNSWithTiming(t, 0, 100*time.Millisecond)
	file, err := os.OpenFile(dns, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, chunk := range []string{`{"servers":`, `[`, `"1.1.1.1"`, `]`} {
		if _, err := file.WriteString(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	if _, err := file.WriteString(`}`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	events.wantReload(t, "completed multi-write DNS document")
	select {
	case err := <-events.rejected:
		t.Fatalf("partial document was validated: %v", err)
	default:
	}
}
