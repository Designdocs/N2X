package panel

import (
	"encoding/json"
	"testing"

	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestNormalizeLegacyXHTTPSettings_ConvertsEmptyArraysToObjects(t *testing.T) {
	raw := json.RawMessage(`{
		"host": "example.com",
		"path": "/yourpath",
		"mode": "auto",
		"extra": {
			"headers": [],
			"noGRPCHeader": false,
			"noSSEHeader": false,
			"xmux": [],
			"downloadSettings": {
				"address": "",
				"port": 443,
				"network": "xhttp",
				"security": "tls",
				"tlsSettings": [],
				"xhttpSettings": {
					"path": "/yourpath"
				},
				"sockopt": []
			}
		}
	}`)

	normalized, err := normalizeLegacyXHTTPSettings("xhttp", raw)
	if err != nil {
		t.Fatalf("normalizeLegacyXHTTPSettings returned error: %v", err)
	}

	var config coreConf.SplitHTTPConfig
	if err := json.Unmarshal(normalized, &config); err != nil {
		t.Fatalf("normalized xhttp settings should unmarshal into SplitHTTPConfig: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(normalized, &payload); err != nil {
		t.Fatalf("normalized payload should remain valid json: %v", err)
	}

	extra, ok := payload["extra"].(map[string]any)
	if !ok {
		t.Fatalf("expected extra to be an object, got %T", payload["extra"])
	}
	if _, ok := extra["headers"].(map[string]any); !ok {
		t.Fatalf("expected extra.headers to be normalized to an object, got %T", extra["headers"])
	}
	if _, ok := extra["xmux"].(map[string]any); !ok {
		t.Fatalf("expected extra.xmux to be normalized to an object, got %T", extra["xmux"])
	}

	downloadSettings, ok := extra["downloadSettings"].(map[string]any)
	if !ok {
		t.Fatalf("expected extra.downloadSettings to be an object, got %T", extra["downloadSettings"])
	}
	if _, ok := downloadSettings["sockopt"].(map[string]any); !ok {
		t.Fatalf("expected downloadSettings.sockopt to be normalized to an object, got %T", downloadSettings["sockopt"])
	}
	if _, ok := downloadSettings["tlsSettings"].(map[string]any); !ok {
		t.Fatalf("expected downloadSettings.tlsSettings to be normalized to an object, got %T", downloadSettings["tlsSettings"])
	}
}

func TestNormalizeLegacyXHTTPSettings_IgnoresOtherNetworks(t *testing.T) {
	raw := json.RawMessage(`{"headers":[]}`)

	normalized, err := normalizeLegacyXHTTPSettings("ws", raw)
	if err != nil {
		t.Fatalf("normalizeLegacyXHTTPSettings returned error: %v", err)
	}
	if string(normalized) != string(raw) {
		t.Fatalf("expected non-xhttp settings to remain unchanged, got %s", string(normalized))
	}
}
