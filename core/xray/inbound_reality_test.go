package xray

import (
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
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
func realitySettingsOf(t *testing.T, options *conf.Options, node *panel.NodeInfo, tag string) *reality.Config {
	t.Helper()
	inbound, err := buildInbound(options, node, tag)
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

	settings := realitySettingsOf(t, transportTestOptions(), node, "trojan-reality")
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

	settings := realitySettingsOf(t, transportTestOptions(), node, "anytls-reality")
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

func TestBuildInboundRealityFallbackParameters(t *testing.T) {
	node := &panel.NodeInfo{
		Type: "trojan", Security: panel.Reality, Common: &panel.CommonNode{ServerPort: 10443},
		Trojan: &panel.TrojanNode{Network: "tcp", Tls: panel.Reality, TlsSettings: realityTlsSettings()},
	}
	options := transportTestOptions()
	options.LimitFallbackUpload = &conf.RealityFallbackLimit{AfterBytes: 100, BytesPerSec: 200, BurstBytesPerSec: 300}
	options.LimitFallbackDownload = &conf.RealityFallbackLimit{AfterBytes: 400, BytesPerSec: 500, BurstBytesPerSec: 600}
	settings := realitySettingsOf(t, options, node, "limited")
	up, down := settings.GetLimitFallbackUpload(), settings.GetLimitFallbackDownload()
	if up.GetAfterBytes() != 100 || up.GetBytesPerSec() != 200 || up.GetBurstBytesPerSec() != 300 ||
		down.GetAfterBytes() != 400 || down.GetBytesPerSec() != 500 || down.GetBurstBytesPerSec() != 600 {
		t.Fatalf("unexpected Xray fallback settings: up=%v down=%v", up, down)
	}
	node.Security = panel.Tls
	if _, err := buildInbound(options, node, "plain-tls"); err == nil || !strings.Contains(err.Error(), "require a REALITY inbound") {
		t.Fatalf("expected fallback configuration error for plain TLS, got %v", err)
	}
}

func TestRealityWebsiteSkipsUnavailableRoutes(t *testing.T) {
	node := &panel.NodeInfo{Type: "vless", Security: panel.Reality, Common: &panel.CommonNode{ServerPort: 443, Host: "site.example"}, VAllss: &panel.VAllssNode{Tls: panel.Reality, Network: "tcp", TlsSettings: realityTlsSettings()}}
	options := transportTestOptions()
	for _, w := range []*conf.RealityWebsite{
		{Port: 443}, {Port: 65536}, {ServerName: "*.example"}, {ServerName: "WWW.EXAMPLE.COM"}, {Disabled: true},
	} {
		options.RealityWebsite = w
		if _, err := buildInbound(options, node, "split"); err != nil {
			t.Fatal(err)
		}
		if split := resolveRealityWebsite(options, node, "tcp"); split != nil {
			t.Fatalf("unexpected split: %v", split)
		}
	}
	options.RealityWebsite = nil
	auto := resolveRealityWebsite(options, node, "tcp")
	if auto == nil || auto.Address != "" || auto.ServerName != "site.example" {
		t.Fatalf("missing auto config: %v", auto)
	}
	node.Common.Host = ""
	if split := resolveRealityWebsite(options, node, "tcp"); split != nil {
		t.Fatalf("unidentified host: %v", split)
	}
}
