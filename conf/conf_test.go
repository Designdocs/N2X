package conf

import (
	"encoding/json"
	"errors"
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
	return New(), writeDoc(t, validDoc())
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
	stop, err := c.Watch(filepath.Join(t.TempDir(), "does-not-exist.json"), "", ValidateOptions{}, func() {}, nil)
	if err == nil {
		stop()
		t.Fatal("expected an error when watching a file that does not exist")
	}
	if stop != nil {
		t.Error("no stop function should be returned when Watch fails")
	}
}

// A missing DNS file is watched through its directory; only a directory that
// does not exist either fails.
func TestConf_WatchRejectsDNSFileInMissingDirectory(t *testing.T) {
	c, config := newWatchedConfig(t)

	stop, err := c.Watch(config, filepath.Join(filepath.Dir(config), "missing-dir", "dns.json"), ValidateOptions{}, func() {}, nil)
	if err == nil {
		stop()
		t.Fatal("expected an error when the dns file directory does not exist")
	}
}

// A failed Watch must not leave the watcher goroutine behind.
func TestConf_WatchLeavesNoGoroutineWhenItFails(t *testing.T) {
	c, config := newWatchedConfig(t)
	before := runtime.NumGoroutine()

	if _, err := c.Watch(config, filepath.Join(filepath.Dir(config), "missing-dir", "dns.json"), ValidateOptions{}, func() {}, nil); err == nil {
		t.Fatal("expected Watch to fail")
	}
	waitForGoroutines(t, before)
}

func TestConf_WatchStopReleasesGoroutine(t *testing.T) {
	c, config := newWatchedConfig(t)
	before := runtime.NumGoroutine()

	stop, err := c.Watch(config, "", ValidateOptions{}, func() {}, nil)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	stop()
	waitForGoroutines(t, before)
}

func TestConf_WatchStopIsSafeToCallTwice(t *testing.T) {
	c, config := newWatchedConfig(t)

	stop, err := c.Watch(config, "", ValidateOptions{}, func() {}, nil)
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
	stop, err := c.Watch(config, "", ValidateOptions{}, func() {
		select {
		case reloaded <- struct{}{}:
		default:
		}
	}, nil)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer stop()

	writeFile(t, config, debugLevelConfig(t))

	select {
	case <-reloaded:
	case <-time.After(30 * time.Second):
		t.Fatal("reload callback did not fire after the file changed")
	}
	if c.LogConfig.Level != "debug" {
		t.Errorf("reloaded config not applied: Log.Level = %q", c.LogConfig.Level)
	}
}

// debugLevelConfig is a valid config that differs from validDoc only in its
// log level.
func debugLevelConfig(t *testing.T) string {
	t.Helper()
	doc := validDoc()
	doc["Log"] = map[string]any{"Level": "debug"}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return string(data)
}

// A broken edit must never replace the running config: the old one stays in
// effect, reload is not called, and a later fixed edit still goes through.
func TestConf_WatchKeepsRunningConfigWhenReloadIsInvalid(t *testing.T) {
	promptWatch(t)
	c, config := newWatchedConfig(t)
	running, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	*c = *running

	reloaded := make(chan struct{}, 1)
	rejected := make(chan error, 1)
	stop, err := c.Watch(config, "", ValidateOptions{}, func() {
		select {
		case reloaded <- struct{}{}:
		default:
		}
	}, func(err error) {
		select {
		case rejected <- err:
		default:
		}
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer stop()

	writeFile(t, config, `{"Log":{"Level":"debug"},"Cores":[{"Type":"xray"}],"Nodes":[{"NodeTyp":"vless"}]}`)
	select {
	case <-reloaded:
		t.Fatal("reload fired for an invalid config")
	case err := <-rejected:
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("rejected got %T %v, want *ValidationError", err, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("rejected was not called for an invalid config")
	}
	if c.LogConfig.Level != "info" || len(c.NodeConfig) != 1 {
		t.Fatalf("running config was replaced by an invalid one: %+v", c.LogConfig)
	}

	writeFile(t, config, debugLevelConfig(t))
	select {
	case <-reloaded:
	case <-time.After(30 * time.Second):
		t.Fatal("reload did not fire once the config was fixed")
	}
	if c.LogConfig.Level != "debug" {
		t.Errorf("fixed config not applied: Log.Level = %q", c.LogConfig.Level)
	}
}

func TestConf_WatchDoesNotReloadAfterStop(t *testing.T) {
	promptWatch(t)
	c, config := newWatchedConfig(t)

	reloaded := make(chan struct{}, 1)
	stop, err := c.Watch(config, "", ValidateOptions{}, func() {
		select {
		case reloaded <- struct{}{}:
		default:
		}
	}, nil)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	stop()

	writeFile(t, config, debugLevelConfig(t))

	select {
	case <-reloaded:
		t.Fatal("reload fired after the watcher was stopped")
	case <-time.After(500 * time.Millisecond):
	}
}

// stop must not return while a reload is still swapping cores, or shutdown
// would race the reload over the running core.
func TestConf_WatchStopWaitsForRunningReload(t *testing.T) {
	promptWatch(t)
	c, config := newWatchedConfig(t)

	started, release := make(chan struct{}, 1), make(chan struct{})
	stop, err := c.Watch(config, "", ValidateOptions{}, func() {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}, nil)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	writeFile(t, config, debugLevelConfig(t))
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("reload did not start")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop returned while a reload was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return after the reload finished")
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
