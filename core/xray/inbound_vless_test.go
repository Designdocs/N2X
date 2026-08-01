package xray

import (
	"encoding/json"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func postQuantumNode() *panel.NodeInfo {
	return &panel.NodeInfo{
		Type: "vless",
		VAllss: &panel.VAllssNode{
			Network:    "tcp",
			Encryption: "mlkem768x25519plus",
			EncryptionSettings: panel.EncSettings{
				Mode:          "native",
				Ticket:        "600s",
				ServerPadding: "100-111-1111.75-0-111.50-0-3333",
				PrivateKey:    "MC4CAQAwBQYDK2VuBCIEIA",
			},
		},
	}
}

func TestResolveVlessDecryption(t *testing.T) {
	tests := []struct {
		name      string
		node      *panel.NodeInfo
		want      string
		wantError bool
	}{
		{
			name: "no encryption defaults to none",
			node: &panel.NodeInfo{Type: "vless", VAllss: &panel.VAllssNode{Network: "tcp"}},
			want: "none",
		},
		{
			name: "post quantum with padding",
			node: postQuantumNode(),
			want: "mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333.MC4CAQAwBQYDK2VuBCIEIA",
		},
		{
			name: "post quantum without padding",
			node: &panel.NodeInfo{Type: "vless", VAllss: &panel.VAllssNode{
				Network:    "tcp",
				Encryption: "mlkem768x25519plus",
				EncryptionSettings: panel.EncSettings{
					Mode:       "xorpub",
					Ticket:     "0s",
					PrivateKey: "MC4CAQAwBQYDK2VuBCIEIA",
				},
			}},
			want: "mlkem768x25519plus.xorpub.0s.MC4CAQAwBQYDK2VuBCIEIA",
		},
		{
			name: "unknown method rejected",
			node: &panel.NodeInfo{Type: "vless", VAllss: &panel.VAllssNode{
				Network:    "tcp",
				Encryption: "rot13",
			}},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveVlessDecryption(test.node)
			if (err != nil) != test.wantError {
				t.Fatalf("resolveVlessDecryption() error = %v, wantError %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if got != test.want {
				t.Fatalf("resolveVlessDecryption() = %q, want %q", got, test.want)
			}
		})
	}
}

// A VLESS node configured with post-quantum encryption must keep that
// decryption string when fallback is enabled. Hardcoding "none" here made the
// server silently downgrade to plaintext handshakes.
func TestBuildV2rayFallbackPreservesDecryption(t *testing.T) {
	options := &conf.Options{XrayOptions: &conf.XrayOptions{
		EnableFallback:  true,
		FallBackConfigs: []conf.FallBackConfigForXray{{Dest: "127.0.0.1:60443"}},
	}}

	inbound := &coreConf.InboundDetourConfig{}
	if err := buildV2ray(options, postQuantumNode(), inbound); err != nil {
		t.Fatalf("buildV2ray() error = %v", err)
	}

	settings := struct {
		Decryption string            `json:"decryption"`
		Fallbacks  []json.RawMessage `json:"fallbacks"`
	}{}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal vless settings: %v", err)
	}

	want := "mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333.MC4CAQAwBQYDK2VuBCIEIA"
	if settings.Decryption != want {
		t.Fatalf("decryption = %q, want %q", settings.Decryption, want)
	}
	if len(settings.Fallbacks) != 1 {
		t.Fatalf("fallbacks = %d, want 1", len(settings.Fallbacks))
	}
}
