package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

func TestPrepareUpgradeRequiresEveryNodeAndConsumesOnce(t *testing.T) {
	var broken atomic.Value
	broken.Store("user")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		endpoint := filepath.Base(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("node_id") == "188" && endpoint == broken.Load().(string) {
			fmt.Fprint(w, "{}")
			return
		}
		switch endpoint {
		case "config":
			fmt.Fprint(w, `{"server_port":10443}`)
		case "user":
			w.Header().Set("X-Dynamic-Speed-Exemptions-Revision", "9")
			fmt.Fprint(w, `{"users":[{"id":1,"uuid":"fixture-password"}]}`)
		case "alivelist":
			fmt.Fprint(w, `{"alive":{"1":2},"kicked":{}}`)
		default:
			t.Errorf("unexpected request %s", endpoint)
		}
	}))
	defer srv.Close()
	c := conf.New()
	for _, id := range []int{187, 188} {
		c.NodeConfig = append(c.NodeConfig, conf.NodeConfig{ApiConfig: conf.ApiConfig{NodeID: id, NodeType: "anytls", APIHost: srv.URL, Key: "fixture-key"}})
	}
	path := filepath.Join(t.TempDir(), "handoff")
	for _, endpoint := range []string{"config", "user", "alivelist"} {
		broken.Store(endpoint)
		err := prepareUpgrade(c, path)
		if err == nil || !strings.Contains(err.Error(), "188") {
			t.Fatalf("%s: %v", endpoint, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("partial preparation published a handoff")
		}
	}
	broken.Store("")
	if err := prepareUpgrade(c, path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode: %v %v", st, err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(original), "fixture-key") {
		t.Fatal("snapshot contains panel token")
	}
	initialCalls := calls.Load()
	c.NodeConfig[0].ApiConfig.Key = "changed"
	if _, err := readUpgradeData(c, path, false); err == nil {
		t.Fatal("accepted configuration change")
	}
	c.NodeConfig[0].ApiConfig.Key = "fixture-key"
	var stale upgradeData
	if err = json.Unmarshal(original, &stale); err != nil {
		t.Fatal(err)
	}
	stale.Created = time.Now().Add(-upgradeDataLifetime)
	expired, _ := json.Marshal(stale)
	if err = os.WriteFile(path, expired, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readUpgradeData(c, path, false); err == nil {
		t.Fatal("accepted expired handoff")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpgradeData(c, path, false); err != nil {
		t.Fatal(err)
	}
	data, err := readUpgradeData(c, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("handoff reusable after startup")
	}
	client, err := panel.New(&c.NodeConfig[1].ApiConfig)
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.RestorePrepared(&data[1])
	if err != nil || info.Common.ServerPort != 10443 || client.UserExemptionsRevision() != 9 || data[1].Devices.Alive[1] != 2 || len(data[1].Users) != 1 || calls.Load() != initialCalls {
		t.Fatalf("restore: %v requests=%d (was %d)", err, calls.Load(), initialCalls)
	}
}
