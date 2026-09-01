package panel

import "testing"

// Panels omit the tls field entirely on ordinary TLS trojan/anytls nodes, so
// only an explicit REALITY selection may move a node off the TLS default —
// reading a missing field as "no security" would silently drop TLS on every
// existing node.
func TestSecurityFromTLS(t *testing.T) {
	tests := []struct {
		name string
		tls  int
		want int
	}{
		{name: "missing field keeps tls", tls: 0, want: Tls},
		{name: "explicit tls", tls: Tls, want: Tls},
		{name: "reality", tls: Reality, want: Reality},
		{name: "unknown value keeps tls", tls: 7, want: Tls},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securityFromTLS(tt.tls); got != tt.want {
				t.Fatalf("securityFromTLS(%d) = %d, want %d", tt.tls, got, tt.want)
			}
		})
	}
}

func TestRealityParams(t *testing.T) {
	settings := TlsSettings{ServerName: "www.example.com", ServerPort: "443", ShortId: "0123456789abcdef"}

	tests := []struct {
		name string
		node *NodeInfo
		want bool
	}{
		{
			name: "vless",
			node: &NodeInfo{Type: "vless", VAllss: &VAllssNode{TlsSettings: settings}},
			want: true,
		},
		{
			name: "trojan",
			node: &NodeInfo{Type: "trojan", Trojan: &TrojanNode{TlsSettings: settings}},
			want: true,
		},
		{
			name: "anytls",
			node: &NodeInfo{Type: "anytls", AnyTls: &AnyTlsNode{TlsSettings: settings}},
			want: true,
		},
		{
			name: "shadowsocks carries no reality settings",
			node: &NodeInfo{Type: "shadowsocks", Shadowsocks: &ShadowsocksNode{}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := tt.node.RealityParams()
			if ok != tt.want {
				t.Fatalf("RealityParams() ok = %v, want %v", ok, tt.want)
			}
			if ok && got.ServerName != settings.ServerName {
				t.Fatalf("server name = %q, want %q", got.ServerName, settings.ServerName)
			}
		})
	}
}
