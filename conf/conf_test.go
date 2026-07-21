package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
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

// Watch reports why it could not start. The reload path itself is not covered
// here: it sleeps 5s and debounces for 10s inside the goroutine, so asserting
// on it makes the test sensitive to machine load. An earlier attempt passed in
// isolation but failed under `go test ./...`. Covering it properly needs those
// delays injectable, which is a change to Watch rather than to this test.
func TestConf_WatchRejectsMissingFile(t *testing.T) {
	c := New()
	err := c.Watch(filepath.Join(t.TempDir(), "does-not-exist.json"), "", func() {})
	if err == nil {
		t.Fatal("expected an error when watching a file that does not exist")
	}
}

func TestConf_WatchRejectsMissingDNSFile(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	writeFile(t, config, "{}")

	c := New()
	err := c.Watch(config, filepath.Join(dir, "missing-dns.json"), func() {})
	if err == nil {
		t.Fatal("expected an error when the dns file does not exist")
	}
}

func TestConf_WatchAcceptsExistingFile(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	writeFile(t, config, "{}")

	c := New()
	if err := c.Watch(config, "", func() {}); err != nil {
		t.Fatalf("watching an existing file: %v", err)
	}
}
