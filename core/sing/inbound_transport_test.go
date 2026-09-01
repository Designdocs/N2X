package sing

import (
	"strings"
	"testing"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
)

// A transport the sing core cannot serve must fail the node build. Silently
// falling back to plain TCP produces a listener that every client fails to
// reach, with nothing in the log to explain it.
func TestBuildV2RayTransportRejectsUnsupportedNetwork(t *testing.T) {
	for _, network := range []string{"xhttp", "splithttp", "kcp", "quic", "h2"} {
		t.Run(network, func(t *testing.T) {
			_, err := buildV2RayTransport(network, json.RawMessage(`{}`))
			if err == nil {
				t.Fatalf("buildV2RayTransport(%q) returned no error, want one", network)
			}
			if !strings.Contains(err.Error(), network) {
				t.Fatalf("error %q does not name the rejected transport %q", err, network)
			}
		})
	}
}

func TestBuildV2RayTransportAcceptsSupportedNetworks(t *testing.T) {
	tests := []struct {
		network  string
		settings string
		wantType string
	}{
		{network: "", settings: "", wantType: ""},
		{network: "tcp", settings: "", wantType: ""},
		{network: "ws", settings: `{"path":"/ws"}`, wantType: "ws"},
		{network: "grpc", settings: `{"serviceName":"n2x"}`, wantType: "grpc"},
		{network: "httpupgrade", settings: `{"path":"/up"}`, wantType: "httpupgrade"},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			got, err := buildV2RayTransport(tt.network, json.RawMessage(tt.settings))
			if err != nil {
				t.Fatalf("buildV2RayTransport(%q) error = %v", tt.network, err)
			}
			if got.Type != tt.wantType {
				t.Fatalf("transport type = %q, want %q", got.Type, tt.wantType)
			}
		})
	}
}

// The node build must surface the rejection, not swallow it.
func TestGetInboundOptionsRejectsUnsupportedTransport(t *testing.T) {
	info := testNode("vless", panel.Tls)
	info.VAllss = &panel.VAllssNode{Network: "xhttp", NetworkSettings: json.RawMessage(`{}`)}

	if _, err := getInboundOptions("vless-xhttp", info, testOptions()); err == nil {
		t.Fatal("getInboundOptions returned no error for an xhttp node, want one")
	}
}
