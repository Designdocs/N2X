package panel

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

// panelHysteriaBody mirrors what X-Board's UniProxy config endpoint returns
// for a Hysteria node: one node type carrying a version field, with the obfs
// shape differing between the two generations.
func panelHysteriaBody(version int) string {
	common := `"host": "kr.example.com",
		"server_port": 10443,
		"server_name": "kr.example.com",
		"up_mbps": 100,
		"down_mbps": 100,
		"tls_settings": {"server_name": "kr.example.com"},
		"base_config": {"push_interval": 60, "pull_interval": 60}`
	if version == 2 {
		return `{"version": 2, "obfs": "salamander", "obfs-password": "s3cret", ` + common + `}`
	}
	return `{"version": 1, "obfs": "v1-obfs-password", ` + common + `}`
}

func newHysteriaTestClient(t *testing.T, nodeType, body string) *Client {
	t.Helper()
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: nodeType,
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	}))
	return client
}

// TestClientAcceptsNewNodeTypes guards the allowlist in New: a type the core
// can serve must not be rejected before the panel is ever contacted.
func TestClientAcceptsNewNodeTypes(t *testing.T) {
	for _, nodeType := range []string{
		"hysteria", "hysteria2", "tuic", "shadowtls", "naive",
		"vmess", "vless", "trojan", "shadowsocks", "anytls", "artx",
	} {
		if _, err := New(&conf.ApiConfig{
			APIHost:  "http://panel.test",
			Key:      "token",
			NodeType: nodeType,
			NodeID:   1,
		}); err != nil {
			t.Errorf("node type %q was rejected: %v", nodeType, err)
		}
	}

	if _, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "nonsense",
		NodeID:   1,
	}); err == nil {
		t.Error("an unknown node type should still be rejected")
	}
}

// TestGetNodeInfoResolvesHysteriaVersion is the regression test for the
// panel's data model: Hysteria and Hysteria2 are one node type distinguished
// by a version field, and the resolved node.Type is what the core selector
// routes on.
func TestGetNodeInfoResolvesHysteriaVersion(t *testing.T) {
	tests := []struct {
		name       string
		nodeType   string
		body       string
		wantType   string
		wantV2Obfs string
		wantV1Obfs string
	}{
		{
			name:       "panel says v2 for a hysteria node",
			nodeType:   "hysteria",
			body:       panelHysteriaBody(2),
			wantType:   "hysteria2",
			wantV2Obfs: "salamander",
		},
		{
			name:       "panel says v1 for a hysteria node",
			nodeType:   "hysteria",
			body:       panelHysteriaBody(1),
			wantType:   "hysteria",
			wantV1Obfs: "v1-obfs-password",
		},
		{
			// The operator configured hysteria2 but the panel pinned the node
			// to v1; the panel is authoritative.
			name:       "panel version overrides the configured type",
			nodeType:   "hysteria2",
			body:       panelHysteriaBody(1),
			wantType:   "hysteria",
			wantV1Obfs: "v1-obfs-password",
		},
		{
			// A panel that models the generation as its own node type sends
			// no version field.
			name:     "no version falls back to the configured type",
			nodeType: "hysteria2",
			body:     `{"host": "h.example.com", "server_port": 443, "up_mbps": 50, "down_mbps": 50}`,
			wantType: "hysteria2",
		},
		{
			name:     "no version on a hysteria node stays v1",
			nodeType: "hysteria",
			body:     `{"host": "h.example.com", "server_port": 443, "up_mbps": 50, "down_mbps": 50}`,
			wantType: "hysteria",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newHysteriaTestClient(t, tt.nodeType, tt.body)
			node, err := client.GetNodeInfo()
			if err != nil {
				t.Fatalf("GetNodeInfo failed: %v", err)
			}
			if node.Type != tt.wantType {
				t.Fatalf("node.Type = %q, want %q", node.Type, tt.wantType)
			}
			if node.Security != Tls {
				t.Fatalf("hysteria must be served over TLS, got security %d", node.Security)
			}

			switch tt.wantType {
			case "hysteria2":
				if node.Hysteria2 == nil {
					t.Fatal("Hysteria2 settings were not populated")
				}
				if node.Hysteria != nil {
					t.Fatal("v1 settings leaked onto a v2 node")
				}
				if node.Hysteria2.ObfsType != tt.wantV2Obfs {
					t.Fatalf("obfs type = %q, want %q", node.Hysteria2.ObfsType, tt.wantV2Obfs)
				}
			case "hysteria":
				if node.Hysteria == nil {
					t.Fatal("Hysteria settings were not populated")
				}
				if node.Hysteria2 != nil {
					t.Fatal("v2 settings leaked onto a v1 node")
				}
				if node.Hysteria.Obfs != tt.wantV1Obfs {
					t.Fatalf("obfs = %q, want %q", node.Hysteria.Obfs, tt.wantV1Obfs)
				}
			}
		})
	}
}

// TestGetNodeInfoRejectsUnsupportedTuicVersion keeps a v4 node from being
// silently served as v5, which would fail every client handshake.
func TestGetNodeInfoRejectsUnsupportedTuicVersion(t *testing.T) {
	body := `{"version": 4, "host": "t.example.com", "server_port": 443,
		"congestion_control": "bbr", "tls_settings": {"server_name": "t.example.com"}}`
	client := newHysteriaTestClient(t, "tuic", body)

	if _, err := client.GetNodeInfo(); err == nil {
		t.Fatal("tuic v4 should be rejected, sing-box only implements v5")
	} else if !strings.Contains(err.Error(), "v5") {
		t.Fatalf("the error should name the supported version, got: %v", err)
	}

	// v5 and an unset version must both still work.
	for _, v := range []string{`"version": 5,`, ``} {
		client := newHysteriaTestClient(t, "tuic", `{`+v+`"host": "t.example.com",
			"server_port": 443, "congestion_control": "bbr",
			"tls_settings": {"server_name": "t.example.com"}}`)
		node, err := client.GetNodeInfo()
		if err != nil {
			t.Fatalf("tuic with %q was rejected: %v", v, err)
		}
		if node.Tuic == nil {
			t.Fatalf("tuic with %q did not populate settings", v)
		}
	}
}
