package conf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchRouteConfigSaves(t *testing.T) {
	promptWatch(t)
	dir := t.TempDir()
	route := filepath.Join(dir, "route.json")
	writeFile(t, route, `{"rules":[]}`)
	doc := validDoc()
	docCore(doc, 0)["RouteConfigPath"] = route
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
	t.Cleanup(stop)

	writeFile(t, route, `{"rules":[}`)
	var invalid *ValidationError
	if err := events.wantReject(t, "invalid route JSON"); !errors.As(err, &invalid) || invalid.Issues[0].Path != "Cores[0].RouteConfigPath" {
		t.Fatalf("expected a route validation issue, got %v", err)
	}
	const updated = `{"rules":[{"type":"field","domain":["domain:example.org"],"outboundTag":"sk5-unlock-2"}]}`
	replace := func(path, data string) {
		t.Helper()
		tmp := path + ".tmp"
		writeFile(t, tmp, data)
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	// Replacing the file must trigger the reload and keep it watched.
	replace(route, updated)
	events.wantReload(t, "route replaced atomically")
	writeFile(t, route, `{"rules":[]}`)
	events.wantReload(t, "route written after being replaced")

	nextRoute := filepath.Join(t.TempDir(), "custom.json")
	writeFile(t, nextRoute, `{"rules":[]}`)
	docCore(doc, 0)["RouteConfigPath"] = nextRoute
	writeFile(t, config, mustJSON(t, doc))
	events.wantReload(t, "route path changed in main config")
	replace(nextRoute, updated)
	events.wantReload(t, "new route path saved")

	// A different file in the watched directory must never invoke reload.
	writeFile(t, filepath.Join(filepath.Dir(nextRoute), "other.json"), `{"rules":[}`)
	select {
	case <-events.reloaded:
		t.Fatal("unrelated file triggered a reload")
	case err := <-events.rejected:
		t.Fatalf("unrelated file triggered rejection: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}
