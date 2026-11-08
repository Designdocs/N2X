package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchOutboundsAppliesFileWithoutRebuilding(t *testing.T) {
	promptWatch(t)
	path := filepath.Join(t.TempDir(), "custom_outbound.json")
	writeFile(t, path, `[{"tag":"direct","protocol":"freedom"}]`)
	doc := validDoc()
	docCore(doc, 0)["OutboundConfigPath"] = path
	config := writeDoc(t, doc)
	running, err := LoadValidated(config, ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalNodes := &running.NodeConfig[0]
	const candidate = `[{"tag":"blocked","protocol":"blackhole"}]`
	applied := make(chan struct{}, 2)
	rejected := make(chan error, 2)
	rebuilt := make(chan struct{}, 2)
	stop, err := running.WatchWithError(config, "", ValidateOptions{
		ReloadOutbounds: func(next *Conf, paths map[string]struct{}) error {
			if _, ok := paths[path]; len(paths) != 1 || !ok {
				return fmt.Errorf("unexpected files %v", paths)
			}
			data, err := next.CoresConfig[0].XrayConfig.ReadOutboundConfig()
			if err != nil || string(data) != candidate {
				return fmt.Errorf("unexpected candidate %q: %v", data, err)
			}
			applied <- struct{}{}
			return nil
		},
	}, func() error {
		rebuilt <- struct{}{}
		return nil
	}, func(err error) { rejected <- err })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	writeFile(t, path, `[{`)
	select {
	case <-rejected:
	case <-rebuilt:
		t.Fatal("malformed outbound rebuilt the core")
	case <-applied:
		t.Fatal("malformed outbound reached the runtime")
	case <-time.After(3 * time.Second):
		t.Fatal("malformed outbound was not detected")
	}
	writeFile(t, path+".tmp", candidate)
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applied:
	case err := <-rejected:
		t.Fatal(err)
	case <-rebuilt:
		t.Fatal("outbound-only edit rebuilt the core")
	case <-time.After(3 * time.Second):
		t.Fatal("atomic save did not reach the runtime")
	}
	writeFile(t, path, "\n"+candidate+"\n")
	select {
	case <-applied:
		t.Fatal("formatting-only save applied a second time")
	case err := <-rejected:
		t.Fatal(err)
	case <-rebuilt:
		t.Fatal("formatting-only save rebuilt the core")
	case <-time.After(100 * time.Millisecond):
	}
	stop()
	if &running.NodeConfig[0] != originalNodes {
		t.Fatal("outbound hot reload replaced the running node configuration")
	}
}
