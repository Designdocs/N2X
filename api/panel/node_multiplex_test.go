package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestGetNodeInfoMultiplex(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		enabled bool
		padding bool
	}{
		{"missing", "", false, false},
		{"null", "null", false, false},
		{"off", `{"enabled":false,"protocol":"yamux"}`, false, false},
		{"on", `{"enabled":true,"protocol":"yamux","max_connections":4}`, true, false},
		{"padded", `{"enabled":true,"padding":true}`, true, true},
		{"string switch", `{"enabled":"1"}`, true, false},
		{"malformed", `"yes"`, false, false},
	}
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, tc := range cases {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				client, err := New(&conf.ApiConfig{APIHost: "http://panel.test", Key: "token", NodeType: protocol, NodeID: 1})
				if err != nil {
					t.Fatal(err)
				}
				body := `{"server_port":443,"network":"ws","base_config":{"push_interval":60,"pull_interval":60}`
				if tc.value != "" {
					body += `,"multiplex":` + tc.value
				}
				body += "}"
				client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) { return textResponse(r, http.StatusOK, body), nil }))
				node, err := client.GetNodeInfo()
				if err != nil {
					t.Fatalf("a multiplex value must never fail the node: %v", err)
				}
				if got := node.Common.MultiplexEnabled(); got != tc.enabled {
					t.Fatalf("enabled = %v, want %v", got, tc.enabled)
				}
				if tc.enabled && node.Common.Multiplex.Padding != tc.padding {
					t.Fatalf("padding = %v, want %v", node.Common.Multiplex.Padding, tc.padding)
				}
			})
		}
	}
}
