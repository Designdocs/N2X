package panel

import (
	"testing"
	"time"

	"encoding/json"
)

// Panels send durations either as a Go duration string or as a bare number of
// seconds, and both have to mean the same thing.
func TestDurationUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		body string
		want time.Duration
	}{
		{name: "duration string", body: `{"heartbeat":"10s"}`, want: 10 * time.Second},
		{name: "minutes", body: `{"heartbeat":"2m"}`, want: 2 * time.Minute},
		{name: "seconds as number", body: `{"heartbeat":10}`, want: 10 * time.Second},
		{name: "fractional seconds", body: `{"heartbeat":0.5}`, want: 500 * time.Millisecond},
		{name: "absent", body: `{}`, want: 0},
		{name: "null", body: `{"heartbeat":null}`, want: 0},
		{name: "empty string", body: `{"heartbeat":""}`, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &TuicNode{}
			if err := json.Unmarshal([]byte(tt.body), node); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if time.Duration(node.Heartbeat) != tt.want {
				t.Fatalf("heartbeat = %v, want %v", time.Duration(node.Heartbeat), tt.want)
			}
		})
	}
}

func TestDurationRejectsGarbage(t *testing.T) {
	node := &TuicNode{}
	if err := json.Unmarshal([]byte(`{"heartbeat":"soon"}`), node); err == nil {
		t.Fatal("unmarshal returned no error for an unparsable duration")
	}
}

func TestHysteriaNodeQUICWindows(t *testing.T) {
	node := &HysteriaNode{}
	body := `{"recv_window_conn":15728640,"recv_window_client":67108864,"max_conn_client":1024,"disable_mtu_discovery":true}`
	if err := json.Unmarshal([]byte(body), node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if node.ReceiveWindowConn != 15728640 || node.ReceiveWindowClient != 67108864 {
		t.Fatalf("windows = %d/%d", node.ReceiveWindowConn, node.ReceiveWindowClient)
	}
	if node.MaxConnClient != 1024 || !node.DisableMTUDiscovery {
		t.Fatalf("conn options = %d/%v", node.MaxConnClient, node.DisableMTUDiscovery)
	}
}

func TestShadowTLSHandshakeForServerName(t *testing.T) {
	node := &ShadowTLSNode{}
	body := `{"handshake_for_server_name":{"www.apple.com":{"server":"www.apple.com","server_port":443}}}`
	if err := json.Unmarshal([]byte(body), node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	handshake, ok := node.HandshakeForServerName["www.apple.com"]
	if !ok {
		t.Fatalf("handshake map = %v", node.HandshakeForServerName)
	}
	if handshake.Server != "www.apple.com" || handshake.ServerPort != 443 {
		t.Fatalf("handshake = %#v", handshake)
	}
}
