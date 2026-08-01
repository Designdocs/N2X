package xray

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

const defaultDecoyOrigin = "http://127.0.0.1:60443/"

func TestEnableTransportDecoyFallback(t *testing.T) {
	tests := []struct {
		name    string
		options *conf.XrayOptions
		network string
		want    string
	}{
		{name: "nil options", network: "ws"},
		{name: "switch off", options: &conf.XrayOptions{}, network: "ws"},
		{
			name:    "ws",
			options: &conf.XrayOptions{DecoyFallback: true},
			network: "ws",
			want:    defaultDecoyOrigin,
		},
		{
			name:    "xhttp",
			options: &conf.XrayOptions{DecoyFallback: true},
			network: "xhttp",
			want:    defaultDecoyOrigin,
		},
		{
			name:    "splithttp is the same transport under its old name",
			options: &conf.XrayOptions{DecoyFallback: true},
			network: "splithttp",
			want:    defaultDecoyOrigin,
		},
		{
			name:    "case and whitespace tolerated",
			options: &conf.XrayOptions{DecoyFallback: true},
			network: "  XHTTP ",
			want:    defaultDecoyOrigin,
		},
		// tcp reaches the decoy through the protocol level fallbacks list, so
		// turning on the transport hook as well would be redundant.
		{name: "tcp", options: &conf.XrayOptions{DecoyFallback: true}, network: "tcp"},
		// grpc has no equivalent rejection hook, and httpupgrade rejects on a raw
		// connection rather than through an http.Handler. Neither is covered.
		{name: "grpc", options: &conf.XrayOptions{DecoyFallback: true}, network: "grpc"},
		{name: "httpupgrade", options: &conf.XrayOptions{DecoyFallback: true}, network: "httpupgrade"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(decoy.ListenAddressEnvironment, "")
			t.Setenv(decoyfallback.OriginEnvironment, "")

			if err := enableTransportDecoyFallback(test.options, test.network); err != nil {
				t.Fatalf("enableTransportDecoyFallback() error = %v", err)
			}

			if got := os.Getenv(decoyfallback.OriginEnvironment); got != test.want {
				t.Fatalf("%s = %q, want %q", decoyfallback.OriginEnvironment, got, test.want)
			}
		})
	}
}

func TestEnableTransportDecoyFallbackHonoursCustomListenAddress(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "127.0.0.1:61443")
	t.Setenv(decoyfallback.OriginEnvironment, "")

	options := &conf.XrayOptions{DecoyFallback: true}
	if err := enableTransportDecoyFallback(options, "xhttp"); err != nil {
		t.Fatalf("enableTransportDecoyFallback() error = %v", err)
	}

	want := "http://127.0.0.1:61443/"
	if got := os.Getenv(decoyfallback.OriginEnvironment); got != want {
		t.Fatalf("%s = %q, want %q", decoyfallback.OriginEnvironment, got, want)
	}
}

// A listen address the companion service itself would refuse must surface as a
// startup error, not as a silently disabled fallback discovered months later.
func TestEnableTransportDecoyFallbackRejectsUnusableListenAddress(t *testing.T) {
	tests := []struct {
		name   string
		listen string
	}{
		{name: "off loopback", listen: "192.0.2.1:60443"},
		{name: "no port", listen: "127.0.0.1"},
		{name: "port zero", listen: "127.0.0.1:0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(decoy.ListenAddressEnvironment, test.listen)
			t.Setenv(decoyfallback.OriginEnvironment, "")

			options := &conf.XrayOptions{DecoyFallback: true}
			if err := enableTransportDecoyFallback(options, "ws"); err == nil {
				t.Fatal("enableTransportDecoyFallback() error = nil, want an error")
			}
			if got := os.Getenv(decoyfallback.OriginEnvironment); got != "" {
				t.Fatalf("%s = %q, want it left unset on error", decoyfallback.OriginEnvironment, got)
			}
		})
	}
}

// The contract that spans both repositories: whatever N2X writes to the
// environment has to be an origin the core is willing to parse. Without this
// the fallback would fail open to a 404 and only a packet capture would say why.
func TestTransportFallbackOriginIsAcceptedByTheCore(t *testing.T) {
	for _, listen := range []string{"", "127.0.0.1:61443", "[::1]:60443"} {
		t.Run(listen, func(t *testing.T) {
			t.Setenv(decoy.ListenAddressEnvironment, listen)

			origin, err := decoyTransportFallbackOrigin()
			if err != nil {
				t.Fatalf("decoyTransportFallbackOrigin() error = %v", err)
			}
			if err := decoyfallback.ValidateOrigin(origin); err != nil {
				t.Fatalf("the core rejected origin %q: %v", origin, err)
			}
		})
	}
}

// End to end through the real config builder: one DecoyFallback boolean on an
// xhttp node is all an operator sets.
func TestBuildInboundWiresTransportFallbackForXhttp(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")
	t.Setenv(decoyfallback.OriginEnvironment, "")

	options := &conf.Options{
		ListenIP:    "0.0.0.0",
		XrayOptions: &conf.XrayOptions{DecoyFallback: true},
	}
	node := &panel.NodeInfo{
		Type:   "vless",
		Common: &panel.CommonNode{ServerPort: 443},
		VAllss: &panel.VAllssNode{
			Network:         "xhttp",
			NetworkSettings: json.RawMessage(`{"path":"/xh8k2m"}`),
		},
	}

	if _, err := buildInbound(options, node, "test"); err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}

	if got := os.Getenv(decoyfallback.OriginEnvironment); got != defaultDecoyOrigin {
		t.Fatalf("%s = %q, want %q", decoyfallback.OriginEnvironment, got, defaultDecoyOrigin)
	}
}

func TestBuildInboundLeavesTransportFallbackAloneForTcp(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")
	t.Setenv(decoyfallback.OriginEnvironment, "")

	options := &conf.Options{
		ListenIP:    "0.0.0.0",
		XrayOptions: &conf.XrayOptions{DecoyFallback: true},
	}
	node := &panel.NodeInfo{
		Type:   "vless",
		Common: &panel.CommonNode{ServerPort: 443},
		VAllss: &panel.VAllssNode{
			Network:         "tcp",
			NetworkSettings: json.RawMessage(`{}`),
		},
	}

	if _, err := buildInbound(options, node, "test"); err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}

	if got := os.Getenv(decoyfallback.OriginEnvironment); got != "" {
		t.Fatalf("%s = %q, want it left unset", decoyfallback.OriginEnvironment, got)
	}
}
