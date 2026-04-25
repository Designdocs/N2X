package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

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
