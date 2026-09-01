package panel

import (
	"testing"

	"encoding/json"
)

// Panels disagree on whether a port range arrives as one string, a list, or a
// bare number, so all three decode into the same list.
func TestPortRangesUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "string", body: `{"server_ports":"20000-30000"}`, want: []string{"20000-30000"}},
		{name: "list", body: `{"server_ports":["20000-30000","40000"]}`, want: []string{"20000-30000", "40000"}},
		{name: "number", body: `{"server_ports":20000}`, want: []string{"20000"}},
		{name: "number list", body: `{"server_ports":[20000,30000]}`, want: []string{"20000", "30000"}},
		{name: "absent", body: `{}`, want: nil},
		{name: "null", body: `{"server_ports":null}`, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Hysteria2Node{}
			if err := json.Unmarshal([]byte(tt.body), node); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(node.ServerPorts) != len(tt.want) {
				t.Fatalf("server ports = %v, want %v", node.ServerPorts, tt.want)
			}
			for i := range tt.want {
				if node.ServerPorts[i] != tt.want[i] {
					t.Fatalf("server ports = %v, want %v", node.ServerPorts, tt.want)
				}
			}
		})
	}
}

func TestPortRangesRejectsUnusableValue(t *testing.T) {
	node := &Hysteria2Node{}
	if err := json.Unmarshal([]byte(`{"server_ports":{"from":1}}`), node); err == nil {
		t.Fatal("unmarshal returned no error for an object port range")
	}
}
