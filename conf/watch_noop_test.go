package conf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchSkipsUnchangedConfigAndDNSWrites(t *testing.T) {
	dns := filepath.Join(t.TempDir(), "dns.json")
	writeFile(t, dns, goodDNS)
	_, config, events := watchedDNSConfig(t, dns)
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	// Saving the same config and reformatting the DNS must preserve sessions.
	writeFile(t, config, string(raw))
	writeFile(t, dns, "{\n  \"servers\": [ \"1.1.1.1\" ]\n}")
	select {
	case <-events.reloaded:
		t.Fatal("unchanged files caused a core reload")
	case err := <-events.rejected:
		t.Fatalf("unchanged files rejected: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	writeFile(t, dns, `{"servers":["8.8.8.8"]}`)
	events.wantReload(t, "real DNS change after a skipped write")
}

func TestWatchAppliesEditMadeBetweenLoadAndWatch(t *testing.T) {
	promptWatch(t)
	config := writeDoc(t, validDoc())
	c, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The running core may also have filled in its decoded options.
	c.CoresConfig[0].XrayConfig.AssetPath = "/runtime-only/"
	writeFile(t, config, debugLevelConfig(t))
	events := newWatchEvents()
	stop, err := c.Watch(config, "", ValidateOptions{}, events.reload, events.reject)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	writeFile(t, config, debugLevelConfig(t))
	events.wantReload(t, "edit that was not applied before Watch started")
	if c.LogConfig.Level != "debug" {
		t.Fatal("unapplied startup edit was lost")
	}
}

func TestWatchRetriesFailedReloadOnIdenticalOrRestoredConfig(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "same candidate", true: "restore previous config"}[restore], func(t *testing.T) {
			promptWatch(t)
			doc := validDoc()
			config := writeDoc(t, doc)
			c, err := LoadValidated(config, ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			calls := make(chan int, 3)
			attempt := 0
			stop, err := c.WatchWithError(config, "", ValidateOptions{}, func() error {
				attempt++
				calls <- attempt
				if attempt == 1 {
					return errors.New("listener bind failed")
				}
				return nil
			}, func(err error) { t.Errorf("unexpected rejection: %v", err) })
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			waitAttempt := func(want int) {
				t.Helper()
				select {
				case got := <-calls:
					if got != want {
						t.Fatalf("attempt=%d, want %d", got, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("missing reload attempt %d", want)
				}
			}
			writeFile(t, config, debugLevelConfig(t))
			waitAttempt(1)
			candidate := debugLevelConfig(t)
			if restore {
				candidate = mustJSON(t, doc)
			}
			writeFile(t, config, candidate)
			waitAttempt(2)
			writeFile(t, config, candidate)
			select {
			case <-calls:
				t.Fatal("successful retry was followed by an unnecessary reload")
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

func TestWatchStillAppliesReferencedConfigChanges(t *testing.T) {
	for _, tc := range []struct{ name, core, field, initial, changed string }{
		{"route", "xray", "RouteConfigPath", `{"rules":[]}`, `{"rules":[{"type":"field","port":"443","outboundTag":"direct"}]}`},
		{"outbound", "xray", "OutboundConfigPath", `[]`, `[{"protocol":"freedom","tag":"direct"}]`},
		{"inbound", "xray", "InboundConfigPath", `[]`, `[{"protocol":"socks","port":1080}]`},
		{"sing original", "sing", "OriginalPath", `{}`, `{"outbounds":[{"type":"direct","tag":"direct"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			promptWatch(t)
			dependency := filepath.Join(t.TempDir(), "referenced.json")
			writeFile(t, dependency, tc.initial)
			doc := validDoc()
			doc["Cores"] = []any{map[string]any{"Type": tc.core, tc.field: dependency}}
			docNode(doc, 0)["Core"] = tc.core
			config := writeDoc(t, doc)
			c, err := LoadValidated(config, ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			events := newWatchEvents()
			stop, err := c.Watch(config, "", ValidateOptions{}, events.reload, events.reject)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			writeFile(t, dependency, tc.changed)
			writeFile(t, config, mustJSON(t, doc))
			events.wantReload(t, "referenced config changed without changing its path")
		})
	}
}

func TestWatchComparesEffectiveOptionsAndPreservesRejectedBaseline(t *testing.T) {
	doc := validDoc()
	config := writeDoc(t, doc)
	running, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := snapshotWatchState(running, "")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	reloads, rejections := 0, 0
	apply := func() {
		t.Helper()
		running.reloadChanged(done, config, config, "", ValidateOptions{}, &state,
			func() error { reloads++; return nil }, func(error) { rejections++ })
	}
	// _help, comments, formatting and explicitly writing an existing default
	// change the file but do not change the running proxy configuration.
	doc["_help"] = map[string]any{"note": "updated documentation"}
	docCore(doc, 0)["ConnectionConfig"] = map[string]any{"connIdle": 300}
	writeFile(t, config, "// documentation only\n"+mustJSON(t, doc))
	apply()
	if reloads != 0 || rejections != 0 {
		t.Fatalf("effective no-op: reloads=%d rejections=%d", reloads, rejections)
	}
	// Validation still runs before the no-op check, retaining the last
	// accepted baseline when a write is incomplete or invalid.
	writeFile(t, config, `{"Log":`)
	apply()
	writeFile(t, config, mustJSON(t, doc))
	apply()
	if reloads != 0 || rejections != 1 {
		t.Fatalf("restoring unchanged config: reloads=%d rejections=%d", reloads, rejections)
	}
	docCore(doc, 0)["ConnectionConfig"] = map[string]any{"connIdle": 900}
	writeFile(t, config, mustJSON(t, doc))
	apply()
	if reloads != 1 || running.CoresConfig[0].XrayConfig.ConnectionConfig.ConnIdle != 900 {
		t.Fatal("a real core option change was skipped")
	}
	docNode(doc, 0)["ApiHost"] = "https://different.example.com"
	writeFile(t, config, mustJSON(t, doc))
	apply()
	if reloads != 2 || running.NodeConfig[0].ApiConfig.APIHost != "https://different.example.com" {
		t.Fatal("a real node option change was skipped")
	}
}

func TestWatchSnapshotPreservesUnselectedCoreOptions(t *testing.T) {
	doc := validDoc()
	delete(docNode(doc, 0), "Core")
	config := writeDoc(t, doc)
	c, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotWatchState(c, "")
	if err != nil {
		t.Fatal(err)
	}
	// RawOptions also needs semantic comparison when no core was selected.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(c.NodeConfig[0].Options.RawOptions, &raw); err != nil {
		t.Fatal(err)
	}
	c.NodeConfig[0].Options.RawOptions, err = json.MarshalIndent(raw, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	after, err := snapshotWatchState(c, "")
	if err != nil || !before.equal(after) {
		t.Fatalf("raw option formatting changed the snapshot: %v", err)
	}
}
