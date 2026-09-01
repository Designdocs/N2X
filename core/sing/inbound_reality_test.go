package sing

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/sagernet/sing-box/option"
)

func singRealityTlsSettings() panel.TlsSettings {
	return panel.TlsSettings{
		ServerName: "www.example.com",
		Dest:       "www.example.com",
		ServerPort: "443",
		ShortId:    "0123456789abcdef",
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

func TestBuildTLSOptionsTrojanReality(t *testing.T) {
	info := testNode("trojan", panel.Reality)
	info.Trojan = &panel.TrojanNode{Network: "tcp", Tls: panel.Reality, TlsSettings: singRealityTlsSettings()}

	in, err := getInboundOptions("trojan-reality", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts, ok := in.Options.(*option.TrojanInboundOptions)
	if !ok {
		t.Fatalf("options type = %T", in.Options)
	}
	if opts.TLS == nil || opts.TLS.Reality == nil || !opts.TLS.Reality.Enabled {
		t.Fatalf("reality not enabled: %#v", opts.TLS)
	}
	if opts.TLS.ServerName != "www.example.com" {
		t.Fatalf("server name = %q", opts.TLS.ServerName)
	}
	if opts.TLS.Reality.Handshake.Server != "www.example.com" || opts.TLS.Reality.Handshake.ServerPort != 443 {
		t.Fatalf("handshake = %#v", opts.TLS.Reality.Handshake)
	}
}

func TestBuildTLSOptionsAnyTLSReality(t *testing.T) {
	info := testNode("anytls", panel.Reality)
	info.AnyTls = &panel.AnyTlsNode{Tls: panel.Reality, TlsSettings: singRealityTlsSettings()}

	in, err := getInboundOptions("anytls-reality", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts, ok := in.Options.(*option.AnyTLSInboundOptions)
	if !ok {
		t.Fatalf("options type = %T", in.Options)
	}
	if opts.TLS == nil || opts.TLS.Reality == nil || !opts.TLS.Reality.Enabled {
		t.Fatalf("reality not enabled: %#v", opts.TLS)
	}
}

// Shadowsocks carries no REALITY settings; the build must say so instead of
// dereferencing the vmess/vless struct it does not have.
func TestBuildTLSOptionsRealityWithoutSettings(t *testing.T) {
	info := testNode("shadowsocks", panel.Reality)
	info.Shadowsocks = &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}

	if _, err := getInboundOptions("ss-reality", info, testOptions()); err == nil {
		t.Fatal("getInboundOptions returned no error for a node type without REALITY settings")
	}
}
