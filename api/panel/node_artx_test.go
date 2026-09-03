package panel

import (
	"net/http"
	"testing"

	"encoding/json/v2"

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
			"public_host": "public.example.com",
			"public_port": 8443,
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
	if node.ArtX.PublicHost != "public.example.com" || node.ArtX.PublicPort != 8443 {
		t.Fatalf("unexpected ArtX public endpoint: %s:%d", node.ArtX.PublicHost, node.ArtX.PublicPort)
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
	if node.ArtX.UDPMode != "compat" {
		t.Fatalf("expected default UDP mode compat, got %q", node.ArtX.UDPMode)
	}
	if node.ArtX.PublicHost != "" || node.ArtX.PublicPort != 0 {
		t.Fatalf("legacy ArtX response unexpectedly inferred public endpoint: %s:%d", node.ArtX.PublicHost, node.ArtX.PublicPort)
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
			"flow_control": "medium_latency",
			"profile": "balanced",
			"profile_version": 1,
			"udp": true,
			"udp_mode": "native",
			"fallback": {"enabled": true, "origin": "n2x://decoy"},
			"base_config": {"push_interval": 60, "pull_interval": 60}
		}`
		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info failed: %v", err)
	}
	if node.ArtX.Underlay != "artx-wire" || node.ArtX.WireVersion != 1 || !node.ArtX.UDP || node.ArtX.UDPMode != "native" {
		t.Fatalf("unexpected ArtX wire settings: %+v", node.ArtX)
	}
	if node.ArtX.FlowControl != "medium_latency" {
		t.Fatalf("expected medium-latency flow control, got %q", node.ArtX.FlowControl)
	}
	if !node.ArtX.Fallback.Enabled || node.ArtX.Fallback.Origin != "n2x://decoy" {
		t.Fatalf("unexpected ArtX fallback selector: %+v", node.ArtX.Fallback)
	}
}

func TestClientGetNodeInfoDefaultsArtXFlowControlToLegacy(t *testing.T) {
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
			"profile_version": 1,
			"base_config": {"push_interval": 60, "pull_interval": 60}
		}`
		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info failed: %v", err)
	}
	if node.ArtX.FlowControl != "legacy" {
		t.Fatalf("expected legacy flow control, got %q", node.ArtX.FlowControl)
	}
}

func TestNormalizeArtXNodeForcesLegacyFlowControlOutsideWire(t *testing.T) {
	node := &ArtXNode{Underlay: "anytls", FlowControl: "medium_latency"}

	normalizeArtXNode(node)

	if node.FlowControl != "legacy" {
		t.Fatalf("expected non-wire underlay to use legacy flow control, got %q", node.FlowControl)
	}
}

func TestNodeMetricsArtXSerialisesAutoFlowControlFields(t *testing.T) {
	payload, err := json.Marshal(&NodeMetricsArtX{
		ConfiguredFlowControl:      ArtXFlowControlAuto,
		MaxWindowScale:             ArtXAutoWindowScale,
		FlowControlNegotiated:      9,
		FlowControlScales:          []int{1, 0, 4, 3, 1},
		FlowControlPressureCeiling: 3,
		FlowControlAutoFallback:    2,
	})
	if err != nil {
		t.Fatalf("marshal node metrics failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal node metrics failed: %v", err)
	}
	if decoded["configured_flow_control"] != "auto" {
		t.Fatalf("configured_flow_control = %#v, want auto", decoded["configured_flow_control"])
	}
	scales, ok := decoded["flow_control_scales"].([]any)
	if !ok || len(scales) != 5 || scales[2] != float64(4) {
		t.Fatalf("flow_control_scales = %#v, want a five-element array", decoded["flow_control_scales"])
	}
	if decoded["flow_control_pressure_ceiling"] != float64(3) {
		t.Fatalf("flow_control_pressure_ceiling = %#v, want 3", decoded["flow_control_pressure_ceiling"])
	}
	if decoded["flow_control_auto_fallback"] != float64(2) {
		t.Fatalf("flow_control_auto_fallback = %#v, want 2", decoded["flow_control_auto_fallback"])
	}
}

func TestNormalizeArtXNodeKeepsAutoFlowControlOnWire(t *testing.T) {
	node := &ArtXNode{Underlay: "artx-wire", FlowControl: " auto "}

	normalizeArtXNode(node)

	if node.FlowControl != ArtXFlowControlAuto {
		t.Fatalf("flow control = %q, want auto", node.FlowControl)
	}
}
