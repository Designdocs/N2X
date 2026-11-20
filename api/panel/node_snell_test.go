package panel

import (
	"fmt"
	"strings"
	"testing"
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
				node.Snell == nil || node.Snell.Version != SnellVersion || node.Snell.PSK != tc.psk {
				t.Fatal("Snell config did not reach the node")
			}
		})
	}
}
