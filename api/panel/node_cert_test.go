package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestLocalCertConfigRejectsPanelOnlyTLS(t *testing.T) {
	node := &NodeInfo{
		Security:   Tls,
		CertConfig: &conf.CertConfig{CertMode: "self", CertFile: "/panel/cert.pem"},
	}
	options := &conf.Options{CertConfig: &conf.CertConfig{CertMode: "none"}}
	if _, err := node.LocalCertConfig(options); err == nil {
		t.Fatal("panel-only TLS silently fell back to plaintext")
	}
	options.CertConfig = &conf.CertConfig{CertMode: "file", CertFile: "/local/cert.pem"}
	if cert, err := node.LocalCertConfig(options); err != nil || cert != options.CertConfig {
		t.Fatalf("local certificate was not used: %v", err)
	}
	node.CertConfig = nil
	options.CertConfig = &conf.CertConfig{CertMode: "none"}
	if cert, err := node.LocalCertConfig(options); err != nil || cert.CertMode != "none" {
		t.Fatalf("local TLS offload was not preserved: %v", err)
	}
}

func TestClientGetNodeInfoPromotesPanelCertConfig(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "anytls",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}

		body := `{
			"host": "edge.example.com",
			"server_port": 443,
			"server_name": "edge.example.com",
			"tls_settings": {
				"server_name": "edge.example.com"
			},
			"padding_scheme": ["stop=8"],
			"base_config": {
				"push_interval": 60,
				"pull_interval": 60
			},
			"cert_config": {
				"cert_mode": "file",
				"reject_unknown_sni": true,
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
	if node.CertConfig == nil {
		t.Fatal("expected panel cert_config to be promoted to node info")
	}
	if node.CertConfig.CertMode != "file" {
		t.Fatalf("expected panel cert mode file, got %q", node.CertConfig.CertMode)
	}
	if node.CertConfig.CertFile != "/panel/cert.pem" || node.CertConfig.KeyFile != "/panel/key.pem" {
		t.Fatalf("expected panel cert files, got cert=%q key=%q", node.CertConfig.CertFile, node.CertConfig.KeyFile)
	}
	if !node.CertConfig.RejectUnknownSni {
		t.Fatal("expected reject unknown sni from panel cert_config")
	}
	if node.Common.CertConfig != nil {
		t.Fatal("expected common cert_config to be cleared after promotion")
	}
}
