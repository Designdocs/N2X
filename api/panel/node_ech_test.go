package panel

import (
	"encoding/json"
	"testing"
)

func TestMergeLegacyTLSSettings_PrefersLegacyPayload(t *testing.T) {
	legacy := &TlsSettings{
		ServerName: "legacy.example.com",
		Ech: &ECHSettings{
			Enabled: true,
			Key:     "legacy-key",
		},
	}

	merged := mergeLegacyTLSSettings(TlsSettings{ServerName: "current.example.com"}, legacy)

	if merged.ServerName != legacy.ServerName {
		t.Fatalf("expected legacy server name %q, got %q", legacy.ServerName, merged.ServerName)
	}
	if merged.Ech == nil || merged.Ech.Key != legacy.Ech.Key {
		t.Fatalf("expected legacy ech settings to be preserved, got %+v", merged.Ech)
	}
}

func TestAnyTLSNode_UnmarshalECHSettingsFromLatestXBoardShape(t *testing.T) {
	raw := []byte(`{
		"server_name": "edge.example.com",
		"tls_settings": {
			"server_name": "edge.example.com",
			"allow_insecure": false,
			"ech": {
				"enabled": true,
				"config": "config-pem",
				"query_server_name": "public.example.com",
				"key": "key-pem"
			}
		},
		"padding_scheme": ["stop=8"]
	}`)

	var node AnyTlsNode
	if err := json.Unmarshal(raw, &node); err != nil {
		t.Fatalf("unmarshal anytls payload failed: %v", err)
	}

	if node.TlsSettings.ServerName != "edge.example.com" {
		t.Fatalf("expected tls server name to be parsed, got %q", node.TlsSettings.ServerName)
	}
	if node.TlsSettings.Ech == nil {
		t.Fatal("expected ech settings to be parsed")
	}
	if !node.TlsSettings.Ech.Enabled {
		t.Fatal("expected ech.enabled to be true")
	}
	if node.TlsSettings.Ech.QueryServerName != "public.example.com" {
		t.Fatalf("expected ech query server name to be parsed, got %q", node.TlsSettings.Ech.QueryServerName)
	}
	if node.TlsSettings.Ech.Key != "key-pem" {
		t.Fatalf("expected ech key to be parsed, got %q", node.TlsSettings.Ech.Key)
	}
}
