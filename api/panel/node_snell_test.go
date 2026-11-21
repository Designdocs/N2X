package panel

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestSnellNodeConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		psk     string
		valid   bool
	}{
		{"valid v6", 6, "test-shared-key", true},
		{"wrong version", 5, "test-shared-key", false},
		{"missing key", 6, "", false},
		{"UTF-8 byte limit", 6, strings.Repeat("密", 86), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":"snell","server_port":8443,"version":%d,"psk":%q,"base_config":{"push_interval":60,"pull_interval":60}}`, tc.version, tc.psk)
			node, err := newHysteriaTestClient(t, "snell", body).GetNodeInfo()
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid Snell config was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if node.Type != "snell" || node.Security != None || node.Common.ServerPort != 8443 ||
				node.Snell == nil || node.Snell.Version != SnellVersion || node.Snell.PSK != tc.psk ||
				node.Snell.Mode != SnellModeDefault {
				t.Fatal("Snell config did not reach the node")
			}
		})
	}
}

func TestSnellTransportMode(t *testing.T) {
	client, err := New(&conf.ApiConfig{APIHost: "http://panel.test", Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	const config = `{"server_port":8443,"version":6,"psk":"test-shared-key","base_config":{"pull_interval":60,"push_interval":60}`
	var body string
	client.client.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return textResponse(request, http.StatusOK, body), nil
	}))
	body = config + "}"
	if node, err := client.GetNodeInfo(); err != nil || node == nil || node.Snell.Mode != SnellModeDefault {
		t.Fatalf("missing mode must select default: node=%v err=%v", node, err)
	}
	body = config + `,"mode":"default"}`
	if node, err := client.GetNodeInfo(); err != nil || node != nil {
		t.Fatalf("explicit default must preserve the effective config: node=%v err=%v", node, err)
	}
	body = config + `,"mode":"unshaped"}`
	if node, err := client.GetNodeInfo(); err != nil || node == nil || node.Snell.Mode != SnellModeUnshaped {
		t.Fatalf("mode change must reach the node: node=%v err=%v", node, err)
	}
	for _, mode := range []string{"unsafe-raw", "invalid"} {
		body = fmt.Sprintf(`%s,"mode":%q}`, config, mode)
		if node, err := client.GetNodeInfo(); err == nil || node != nil {
			t.Fatalf("unsupported mode %q reached the node: node=%v err=%v", mode, node, err)
		}
	}
}

func TestSnellShadowTLSConfig(t *testing.T) {
	const base = `{"server_port":8443,"version":6,"psk":"test-shared-key","base_config":{"pull_interval":60,"push_interval":60},`
	for _, bad := range []string{
		`"shadowtls":{"handshake":{"server":"cover.example.com"}}}`,
		`"shadowtls":{"password":"outer-key","handshake":{"server":"https://cover.example.com"}}}`,
		`"shadowtls":{"password":"outer-key","handshake":{"server":"cover.example.com","server_port":65536}}}`,
		`"shadowtls":{"password":"outer-key","handshake":{"server":"cover.example.com"},"fallback_server_name":"cover.example.com"}}`,
	} {
		if _, err := newHysteriaTestClient(t, "snell", base+bad).GetNodeInfo(); err == nil {
			t.Fatal("invalid ShadowTLS settings reached the Snell node")
		}
	}
	node, err := newHysteriaTestClient(t, "snell", base+`"shadowtls":{"password":"outer-key","handshake":{"server":"cover.example.com","server_port":8443}}}`).GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if node.Security != None || node.Snell.ShadowTLS == nil ||
		node.Snell.ShadowTLS.Handshake != (ShadowTLSHandshake{Server: "cover.example.com", ServerPort: 8443}) ||
		node.Snell.ShadowTLS.Password != "outer-key" {
		t.Fatal("valid ShadowTLS settings did not reach the Snell node")
	}
}

func TestSnellShadowTLSWebsitePortConflict(t *testing.T) {
	settings := &SnellShadowTLS{Handshake: ShadowTLSHandshake{Server: "127.0.0.1", ServerPort: 443}}
	for _, address := range []string{"0.0.0.0", "::", "127.0.0.1", "::ffff:127.0.0.1"} {
		if err := settings.ValidateListen(address, 443); err == nil {
			t.Errorf("same port on %s should conflict with the loopback origin", address)
		}
	}
	if err := settings.ValidateListen("192.0.2.1", 443); err != nil {
		t.Fatalf("a separate listener address should allow port 443: %v", err)
	}
	if err := settings.ValidateListen("0.0.0.0", 8443); err != nil {
		t.Fatalf("a different listener port should be allowed: %v", err)
	}
}
