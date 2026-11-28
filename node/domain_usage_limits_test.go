package node

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
)

func TestDomainUsageManualOffOverridesDiskRecovery(t *testing.T) {
	billed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			w.Header().Set("X-N2X-Domain-Rate", "2")
			w.WriteHeader(304)
		case "/api/v1/server/UniProxy/push":
			billed <- r.Header.Get("X-N2X-Domain-Usage")
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected report %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, NodeID: 1, NodeType: "vmess", Key: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	c := &Controller{apiClient: client, limiter: new(limiter.Limiter)}
	dir, err := os.MkdirTemp("/tmp", "n2x-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	space := domainusage.ResumeFreeBytes
	m := domainMonitor{owner: c, path: filepath.Join(dir, "usage.db"), disabledFile: filepath.Join(dir, "switch"), free: func(string) (int64, error) { return space, nil }}
	listener, err := domainusage.ListenLocalWithStatus(m.path, "https://pilot.example", 1, client.Domains.Store.Load, m.status)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	checkMenu := func(want string) {
		t.Helper()
		states := domainusage.InstanceStates(dir)
		if len(states) != 1 || states[0].Node != 1 || states[0].State != want {
			t.Fatalf("wanted %q, got %+v", want, states)
		}
	}
	checkMenu("waiting")
	now := time.Now()
	m.tick(now)
	checkMenu("active")
	old := client.Domains.Store.Load()
	if old == nil || c.limiter.DomainUsage.Load() != old {
		t.Fatal("default off")
	}
	f, done := old.Track(1, "secret.example")
	f.Bytes.Add(10)
	done()
	space = domainusage.MinFreeBytes
	m.tick(now)
	if client.Domains.Header() != "disabled" || c.limiter.DomainUsage.Load() != nil || old.Context().Err() == nil {
		t.Fatal("low disk still active")
	}
	checkMenu("disk space")
	if entries, _ := filepath.Glob(filepath.Join(dir, "*.db")); len(entries) != 0 {
		t.Fatal("low disk final write", entries)
	}
	space = domainusage.ResumeFreeBytes - 1
	m.tick(now)
	if client.Domains.Store.Load() != nil {
		t.Fatal("restarted below high watermark")
	}
	checkMenu("disk space")
	space = domainusage.ResumeFreeBytes
	m.tick(now)
	checkMenu("active")
	if err := os.WriteFile(m.disabledFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	space = domainusage.ResumeFreeBytes
	m.tick(now)
	if client.Domains.Store.Load() != nil {
		t.Fatal("manual off overridden")
	}
	checkMenu("manual")
	if err := client.ReportUserTraffic([]panel.UserTraffic{{UID: 1, Download: 123}}); err != nil {
		t.Fatal(err)
	}
	if got := <-billed; got != "disabled" {
		t.Fatal("ordinary billing changed", got)
	}
	if err := client.AnswerDomainQuery(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.disabledFile); err != nil {
		t.Fatal(err)
	}
	m.tick(now)
	next := client.Domains.Store.Load()
	if next == nil || next == old {
		t.Fatal("manual enable failed")
	}
	checkMenu("active")
	next.Pause()
}
