package xray

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestExampleSOCKS5UnlockTemplate(t *testing.T) {
	exampleDir := filepath.Join("..", "..", "example")
	t.Setenv("XRAY_LOCATION_ASSET", exampleDir)

	outboundData, err := os.ReadFile(filepath.Join(exampleDir, "custom_outbound.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"tag": "socks5-unlock"`,
		`"address": "socks5.example.invalid"`,
		`"port": 1080`,
		`"user": "USERNAME"`,
		`"pass": "PASSWORD"`,
	} {
		if !bytes.Contains(outboundData, []byte(expected)) {
			t.Fatalf("missing %s", expected)
		}
	}
	var outbounds []coreConf.OutboundDetourConfig
	if err := json.Unmarshal(outboundData, &outbounds); err != nil {
		t.Fatal(err)
	}
	for i := range outbounds {
		if _, err := outbounds[i].Build(); err != nil {
			t.Fatalf("build outbound %q: %v", outbounds[i].Tag, err)
		}
	}

	routeData, err := os.ReadFile(filepath.Join(exampleDir, "route.json"))
	if err != nil {
		t.Fatal(err)
	}
	unlock := bytes.Index(routeData, []byte(`"outboundTag": "socks5-unlock"`))
	fallback := bytes.Index(routeData, []byte(`"outboundTag": "socks5-warp"`))
	if unlock < 0 || !bytes.Contains(routeData, []byte(`"domain:socks5-unlock.invalid"`)) {
		t.Fatal("missing socks5-unlock route")
	}
	if fallback >= 0 && unlock > fallback {
		t.Fatal("socks5-unlock route must precede the broad WARP route")
	}
	var route coreConf.RouterConfig
	if err := json.Unmarshal(routeData, &route); err != nil {
		t.Fatal(err)
	}
	if _, err := route.Build(); err != nil {
		t.Fatal(err)
	}
}
