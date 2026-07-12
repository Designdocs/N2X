package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestClientGetNodeInfoParsesArtXNodeConfig(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "artx",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.URL.Query().Get("node_type"); got != "artx" {
			t.Fatalf("expected node_type query artx, got %q", got)
		}

		body := `{
			"host": "edge.example.com",
			"server_port": 443,
			"server_name": "edge.example.com",
			"underlay": "anytls",
			"profile": "realtime",
			"profile_version": 2,
			"tls_settings": {
				"server_name": "edge.example.com",
				"allow_insecure": false,
				"ech": {
					"enabled": true,
					"config": "client-config",
					"key": "server-key"
				}
			},
			"padding_scheme": ["stop=8", "0=30-30"],
			"fallback": {
				"enabled": true,
				"origin": "https://fallback.example.com/"
			},
			"behavior": {
				"padding": "managed",
				"keepalive": "jittered",
				"error_response": "fallback"
			},
			"base_config": {
				"push_interval": 60,
				"pull_interval": 60
			},
			"cert_config": {
				"cert_mode": "file",
				"cert_file": "/panel/cert.pem",
				"key_file": "/panel/key.pem"
			}
		}`

		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info failed: %v", err)
	}
	if node.Type != "artx" {
		t.Fatalf("expected node type artx, got %q", node.Type)
	}
	if node.Security != Tls {
		t.Fatalf("expected ArtX to require TLS security, got %d", node.Security)
	}
	if node.ArtX == nil {
		t.Fatal("expected ArtX node payload to be retained")
	}
	if node.AnyTls != nil {
		t.Fatal("expected ArtX not to be stored as an AnyTLS node")
	}
	if node.ArtX.Underlay != "anytls" {
		t.Fatalf("expected underlay anytls, got %q", node.ArtX.Underlay)
	}
	if node.ArtX.Profile != "realtime" {
		t.Fatalf("expected profile realtime, got %q", node.ArtX.Profile)
	}
	if node.ArtX.ProfileVersion != 2 {
		t.Fatalf("expected profile version 2, got %d", node.ArtX.ProfileVersion)
	}
	if len(node.ArtX.PaddingScheme) != 2 {
		t.Fatalf("expected two padding rules, got %d", len(node.ArtX.PaddingScheme))
	}
	if !node.ArtX.Fallback.Enabled || node.ArtX.Fallback.Origin != "https://fallback.example.com/" {
		t.Fatalf("unexpected fallback settings: %+v", node.ArtX.Fallback)
	}
	if node.ArtX.Behavior.ErrorResponse != "fallback" {
		t.Fatalf("expected fallback error response, got %q", node.ArtX.Behavior.ErrorResponse)
	}
	if node.ArtX.TlsSettings.Ech == nil || node.ArtX.TlsSettings.Ech.Key != "server-key" {
		t.Fatalf("expected ArtX ECH settings to be parsed, got %+v", node.ArtX.TlsSettings.Ech)
	}
	if node.CertConfig == nil || node.CertConfig.CertFile != "/panel/cert.pem" {
		t.Fatalf("expected panel cert config to be promoted, got %+v", node.CertConfig)
	}
}

func TestClientGetNodeInfoDefaultsArtXUnderlayAndProfile(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "artx",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{
			"host": "edge.example.com",
			"server_port": 443,
			"server_name": "edge.example.com",
			"tls_settings": {
				"server_name": "edge.example.com"
			},
			"base_config": {
				"push_interval": 60,
				"pull_interval": 60
			}
		}`

		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info failed: %v", err)
	}
	if node.ArtX == nil {
		t.Fatal("expected ArtX node payload to be retained")
	}
	if node.ArtX.Underlay != "anytls" {
		t.Fatalf("expected default underlay anytls, got %q", node.ArtX.Underlay)
	}
	if node.ArtX.Profile != "balanced" {
		t.Fatalf("expected default profile balanced, got %q", node.ArtX.Profile)
	}
	if node.ArtX.ProfileVersion != 1 {
		t.Fatalf("expected default profile version 1, got %d", node.ArtX.ProfileVersion)
	}
}

func TestClientGetNodeInfoParsesArtXWireVersion(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "artx",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{
			"host": "edge.example.com",
			"server_port": 443,
			"server_name": "edge.example.com",
			"underlay": "artx-wire",
			"wire_version": 1,
			"profile": "balanced",
			"profile_version": 1,
			"base_config": {"push_interval": 60, "pull_interval": 60}
		}`
		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info failed: %v", err)
	}
	if node.ArtX.Underlay != "artx-wire" || node.ArtX.WireVersion != 1 {
		t.Fatalf("unexpected ArtX wire settings: %+v", node.ArtX)
	}
}
