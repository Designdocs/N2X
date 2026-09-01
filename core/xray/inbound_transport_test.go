package xray

import (
	"strings"
	"testing"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

func transportTestOptions() *conf.Options {
	return &conf.Options{
		ListenIP:    "127.0.0.1",
		XrayOptions: &conf.XrayOptions{},
	}
}

// A panel that sends no network settings for a plain TCP node must still get a
// working inbound: the stream settings are what carry the transport, and
// leaving them unset used to panic on the proxy-protocol pass below.
func TestBuildInboundVlessWithoutNetworkSettings(t *testing.T) {
	node := &panel.NodeInfo{
		Type:     "vless",
		Security: panel.None,
		Common:   &panel.CommonNode{ServerPort: 10443},
		VAllss:   &panel.VAllssNode{Network: "tcp"},
	}

	if _, err := buildInbound(transportTestOptions(), node, "vless-tcp"); err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
}

// An empty network is a plain TCP node too.
func TestBuildInboundVlessEmptyNetwork(t *testing.T) {
	node := &panel.NodeInfo{
		Type:     "vless",
		Security: panel.None,
		Common:   &panel.CommonNode{ServerPort: 10443},
		VAllss:   &panel.VAllssNode{Network: "", NetworkSettings: json.RawMessage(`{}`)},
	}

	if _, err := buildInbound(transportTestOptions(), node, "vless-empty"); err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
}

// A transport the builder cannot map must be rejected whether or not the panel
// sent settings for it.
func TestBuildInboundRejectsUnsupportedNetwork(t *testing.T) {
	for _, settings := range []string{"", `{}`} {
		node := &panel.NodeInfo{
			Type:     "vless",
			Security: panel.None,
			Common:   &panel.CommonNode{ServerPort: 10443},
			VAllss:   &panel.VAllssNode{Network: "kcp", NetworkSettings: json.RawMessage(settings)},
		}

		_, err := buildInbound(transportTestOptions(), node, "vless-kcp")
		if err == nil {
			t.Fatalf("buildInbound() with settings %q returned no error, want one", settings)
		}
		if !strings.Contains(err.Error(), "kcp") {
			t.Fatalf("error %q does not name the rejected transport", err)
		}
	}
}

func TestBuildInboundTrojanWithoutNetworkSettings(t *testing.T) {
	node := &panel.NodeInfo{
		Type:     "trojan",
		Security: panel.None,
		Common:   &panel.CommonNode{ServerPort: 10443},
		Trojan:   &panel.TrojanNode{Network: "tcp"},
	}

	if _, err := buildInbound(transportTestOptions(), node, "trojan-tcp"); err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
}
