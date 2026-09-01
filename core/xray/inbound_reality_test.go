package xray

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func realityTlsSettings() panel.TlsSettings {
	return panel.TlsSettings{
		ServerName: "www.example.com",
		Dest:       "www.example.com",
		ServerPort: "443",
		ShortId:    "0123456789abcdef",
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

// realitySettingsOf digs the built REALITY config out of an inbound handler.
func realitySettingsOf(t *testing.T, node *panel.NodeInfo, tag string) *reality.Config {
	t.Helper()
	inbound, err := buildInbound(transportTestOptions(), node, tag)
	if err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
	receiverMessage, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatalf("decode receiver settings: %v", err)
	}
	receiver := receiverMessage.(*proxyman.ReceiverConfig)
	if len(receiver.StreamSettings.SecuritySettings) == 0 {
		t.Fatal("no security settings on the stream, want REALITY")
	}
	securityMessage, err := receiver.StreamSettings.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatalf("decode security settings: %v", err)
	}
	settings, ok := securityMessage.(*reality.Config)
	if !ok {
		t.Fatalf("security settings type = %T, want REALITY", securityMessage)
	}
	return settings
}

// REALITY is a stream-level camouflage: a trojan node that the panel pinned to
// it must get the same handshake as a vless one, not plain TLS.
func TestBuildInboundTrojanReality(t *testing.T) {
	node := &panel.NodeInfo{
		Type:     "trojan",
		Security: panel.Reality,
		Common:   &panel.CommonNode{ServerPort: 10443},
		Trojan:   &panel.TrojanNode{Network: "tcp", Tls: panel.Reality, TlsSettings: realityTlsSettings()},
	}

	settings := realitySettingsOf(t, node, "trojan-reality")
	if len(settings.ServerNames) != 1 || settings.ServerNames[0] != "www.example.com" {
		t.Fatalf("server names = %v", settings.ServerNames)
	}
	if len(settings.ShortIds) != 1 {
		t.Fatalf("short ids = %v", settings.ShortIds)
	}
}

func TestBuildInboundAnyTLSReality(t *testing.T) {
	node := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Reality,
		Common:   &panel.CommonNode{ServerPort: 10443},
		AnyTls:   &panel.AnyTlsNode{Tls: panel.Reality, TlsSettings: realityTlsSettings()},
	}

	settings := realitySettingsOf(t, node, "anytls-reality")
	if len(settings.ServerNames) != 1 || settings.ServerNames[0] != "www.example.com" {
		t.Fatalf("server names = %v", settings.ServerNames)
	}
}

// A node type with no REALITY settings must be refused rather than crash on the
// settings struct it does not have.
func TestBuildInboundRealityWithoutSettings(t *testing.T) {
	node := &panel.NodeInfo{
		Type:        "shadowsocks",
		Security:    panel.Reality,
		Common:      &panel.CommonNode{ServerPort: 10443},
		Shadowsocks: &panel.ShadowsocksNode{Cipher: "aes-128-gcm"},
	}

	if _, err := buildInbound(transportTestOptions(), node, "ss-reality"); err == nil {
		t.Fatal("buildInbound() returned no error for a node type without REALITY settings")
	}
}
