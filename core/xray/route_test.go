package xray

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/xtls/xray-core/features/routing"
)

func TestCheckRouteChangesKeepsRunningRouter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	t.Setenv("XRAY_DNS_PATH", "")
	path := filepath.Join(dir, "route.json")
	configPath := filepath.Join(dir, "config.json")
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(configPath, fmt.Sprintf(`{
		"Cores": [{"Type":"xray","AssetPath":%q,"RouteConfigPath":%q}],
		"Nodes": [{"Core":"xray","ApiHost":"https://panel.example.com","ApiKey":"test","NodeID":1,"NodeType":"vless"}]
	}`, dir, path))
	load := func(route string) *conf.Conf {
		t.Helper()
		write(path, route)
		c, err := conf.LoadValidated(configPath, conf.ValidateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	start := func(c *conf.Conf) *Xray {
		t.Helper()
		core, err := New(&c.CoresConfig[0])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = core.Close() })
		if err := core.Start(); err != nil {
			t.Fatal(err)
		}
		return core.(*Xray)
	}
	wantTag := func(c *Xray, tag string) {
		t.Helper()
		rules := c.Server.GetFeature(routing.RouterType()).(routing.Router).ListRule()
		if len(rules) != 1 || rules[0].GetOutboundTag() != tag {
			t.Fatalf("expected one rule for %q, got %v", tag, rules)
		}
	}

	previous := load(`{"rules":[{"type":"field","domain":["domain:example.org"],"outboundTag":"direct"}]}`)
	running := start(previous)
	invalid := load(`{"rules":[{"type":"field","domain":["regexp:("],"outboundTag":"sk5-unlock-2"}]}`)
	if err := vCore.CheckRouteChanges(running, previous.CoresConfig, invalid.CoresConfig); err == nil {
		t.Fatal("invalid routing expression passed reload validation")
	}
	wantTag(running, "direct")

	next := load(`{"rules":[{"type":"field","domain":["domain:example.org"],"outboundTag":"sk5-unlock-2"}]}`)
	write(path, `{"rules":[}`)
	if err := vCore.CheckRouteChanges(running, previous.CoresConfig, next.CoresConfig); err != nil {
		t.Fatal(err)
	}
	wantTag(start(next), "sk5-unlock-2")
}
