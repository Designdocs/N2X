package conf

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newWatchedConfig returns a Conf and a config file for it to watch.
func newWatchedConfig(t *testing.T) (*Conf, string) {
	t.Helper()
	config := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, config, "{}")
	return New(), config
}

// promptWatch collapses Watch's debounce and settle delays so tests do not
// have to wait out the production timings.
func promptWatch(t *testing.T) {
	t.Helper()
	debounce, settle := watchDebounce, watchSettle
	watchDebounce, watchSettle = 0, time.Millisecond
	t.Cleanup(func() { watchDebounce, watchSettle = debounce, settle })
}

func TestConf_LoadFromPath(t *testing.T) {
	// The example config resolves ApiHost/ApiKey from the environment.
	t.Setenv("N2X_API_HOST", "https://panel.example.com")
	t.Setenv("N2X_API_KEY", "test-key")

	c := New()
	if err := c.LoadFromPath("../example/config.json"); err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if len(c.NodeConfig) == 0 {
		t.Error("example config produced no nodes")
	}
	if len(c.CoresConfig) == 0 {
		t.Error("example config produced no cores")
	}
}

func TestConf_WatchRejectsMissingFile(t *testing.T) {
	c := New()
	stop, err := c.Watch(filepath.Join(t.TempDir(), "does-not-exist.json"), "", func() {})
	if err == nil {
		stop()
		t.Fatal("expected an error when watching a file that does not exist")
	}
	if stop != nil {
		t.Error("no stop function should be returned when Watch fails")
	}
}

func TestConf_WatchRejectsMissingDNSFile(t *testing.T) {
	c, config := newWatchedConfig(t)

	stop, err := c.Watch(config, filepath.Join(filepath.Dir(config), "missing-dns.json"), func() {})
	if err == nil {
		stop()
		t.Fatal("expected an error when the dns file does not exist")
	}
}

// A failed Watch must not leave the watcher goroutine behind.
func TestConf_WatchLeavesNoGoroutineWhenItFails(t *testing.T) {
	c, config := newWatchedConfig(t)
	before := runtime.NumGoroutine()

	if _, err := c.Watch(config, filepath.Join(filepath.Dir(config), "missing-dns.json"), func() {}); err == nil {
		t.Fatal("expected Watch to fail")
	}
	waitForGoroutines(t, before)
}

func TestConf_WatchStopReleasesGoroutine(t *testing.T) {
	c, config := newWatchedConfig(t)
	before := runtime.NumGoroutine()

	stop, err := c.Watch(config, "", func() {})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	stop()
	waitForGoroutines(t, before)
}

func TestConf_WatchStopIsSafeToCallTwice(t *testing.T) {
	c, config := newWatchedConfig(t)

	stop, err := c.Watch(config, "", func() {})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	stop()
	stop() // must not panic on a second close
}

func TestConf_WatchFiresReloadOnChange(t *testing.T) {
	promptWatch(t)
	c, config := newWatchedConfig(t)

	reloaded := make(chan struct{}, 1)
	stop, err := c.Watch(config, "", func() {
		select {
		case reloaded <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer stop()

	writeFile(t, config, `{"Log":{"Level":"debug"}}`)

	select {
	case <-reloaded:
	case <-time.After(30 * time.Second):
		t.Fatal("reload callback did not fire after the file changed")
	}
}

func TestConf_WatchDoesNotReloadAfterStop(t *testing.T) {
	promptWatch(t)
	c, config := newWatchedConfig(t)

	reloaded := make(chan struct{}, 1)
	stop, err := c.Watch(config, "", func() {
		select {
		case reloaded <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	stop()

	writeFile(t, config, `{"Log":{"Level":"debug"}}`)

	select {
	case <-reloaded:
		t.Fatal("reload fired after the watcher was stopped")
	case <-time.After(500 * time.Millisecond):
	}
}

// waitForGoroutines waits for the goroutine count to fall back to want.
func waitForGoroutines(t *testing.T, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine still running: want <=%d, got %d", want, runtime.NumGoroutine())
}
