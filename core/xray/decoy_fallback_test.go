package xray

import (
	"encoding/json"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestResolveFallbackDest(t *testing.T) {
	tests := []struct {
		name      string
		dest      string
		env       string
		want      string
		wantError bool
	}{
		{name: "plain host port untouched", dest: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{name: "bare port untouched", dest: "8080", want: "8080"},
		{name: "unix socket untouched", dest: "/dev/shm/web.sock", want: "/dev/shm/web.sock"},
		{name: "selector expands to default", dest: decoy.Selector, want: "127.0.0.1:60443"},
		{name: "selector honours override", dest: decoy.Selector, env: "127.0.0.1:61443", want: "127.0.0.1:61443"},
		{name: "selector with whitespace", dest: "  " + decoy.Selector + "  ", want: "127.0.0.1:60443"},
		{name: "selector rejects non loopback", dest: decoy.Selector, env: "192.0.2.1:60443", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(decoy.ListenAddressEnvironment, test.env)

			got, err := resolveFallbackDest(test.dest)
			if (err != nil) != test.wantError {
				t.Fatalf("resolveFallbackDest() error = %v, wantError %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if got != test.want {
				t.Fatalf("resolveFallbackDest() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildVlessFallbacksExpandsSelector(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	fallbacks, err := buildVlessFallbacks([]conf.FallBackConfigForXray{{Dest: decoy.Selector}})
	if err != nil {
		t.Fatalf("buildVlessFallbacks() error = %v", err)
	}
	if len(fallbacks) != 1 {
		t.Fatalf("fallbacks = %d, want 1", len(fallbacks))
	}

	var dest string
	if err := json.Unmarshal(fallbacks[0].Dest, &dest); err != nil {
		t.Fatalf("unmarshal dest: %v", err)
	}
	if dest != "127.0.0.1:60443" {
		t.Fatalf("dest = %q, want %q", dest, "127.0.0.1:60443")
	}
}

func TestBuildTrojanFallbacksExpandsSelector(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	fallbacks, err := buildTrojanFallbacks([]conf.FallBackConfigForXray{{Dest: decoy.Selector}})
	if err != nil {
		t.Fatalf("buildTrojanFallbacks() error = %v", err)
	}
	if len(fallbacks) != 1 {
		t.Fatalf("fallbacks = %d, want 1", len(fallbacks))
	}

	var dest string
	if err := json.Unmarshal(fallbacks[0].Dest, &dest); err != nil {
		t.Fatalf("unmarshal dest: %v", err)
	}
	if dest != "127.0.0.1:60443" {
		t.Fatalf("dest = %q, want %q", dest, "127.0.0.1:60443")
	}
}

// The whole point of DecoyFallback: one boolean, no FallBackConfigs, and the
// node answers a browser on port 443 with the built-in site.
func TestBuildV2rayDecoyFallbackNeedsNoDestination(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	options := &conf.Options{XrayOptions: &conf.XrayOptions{DecoyFallback: true}}
	node := &panel.NodeInfo{Type: "vless", VAllss: &panel.VAllssNode{Network: "tcp"}}

	inbound := &coreConf.InboundDetourConfig{}
	if err := buildV2ray(options, node, inbound); err != nil {
		t.Fatalf("buildV2ray() error = %v", err)
	}

	settings := struct {
		Decryption string `json:"decryption"`
		Fallbacks  []struct {
			Dest string `json:"dest"`
		} `json:"fallbacks"`
	}{}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal vless settings: %v", err)
	}

	if settings.Decryption != "none" {
		t.Fatalf("decryption = %q, want %q", settings.Decryption, "none")
	}
	if len(settings.Fallbacks) != 1 {
		t.Fatalf("fallbacks = %d, want 1", len(settings.Fallbacks))
	}
	if settings.Fallbacks[0].Dest != "127.0.0.1:60443" {
		t.Fatalf("dest = %q, want %q", settings.Fallbacks[0].Dest, "127.0.0.1:60443")
	}
}

func TestBuildTrojanDecoyFallbackNeedsNoDestination(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	options := &conf.Options{XrayOptions: &conf.XrayOptions{DecoyFallback: true}}
	node := &panel.NodeInfo{Type: "trojan", Trojan: &panel.TrojanNode{
		Network:         "tcp",
		NetworkSettings: json.RawMessage(`{}`),
	}}

	inbound := &coreConf.InboundDetourConfig{}
	if err := buildTrojan(options, node, inbound); err != nil {
		t.Fatalf("buildTrojan() error = %v", err)
	}

	settings := struct {
		Fallbacks []struct {
			Dest string `json:"dest"`
		} `json:"fallbacks"`
	}{}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal trojan settings: %v", err)
	}

	if len(settings.Fallbacks) != 1 {
		t.Fatalf("fallbacks = %d, want 1", len(settings.Fallbacks))
	}
	if settings.Fallbacks[0].Dest != "127.0.0.1:60443" {
		t.Fatalf("dest = %q, want %q", settings.Fallbacks[0].Dest, "127.0.0.1:60443")
	}
}
