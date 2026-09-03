package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

// A reload that dies halfway leaves the node unbound while GetNodeInfo has
// already committed the new body hash, so the plain retry is a no-op and the
// node stays dark. InvalidateNodeInfoCache is what the controller reaches for
// to make the next pull rebuild it.
func TestInvalidateNodeInfoCacheReopensAnIdenticalConfig(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "artx",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("create panel client failed: %v", err)
	}

	const body = `{
		"host": "edge.example.com",
		"server_port": 443,
		"server_name": "edge.example.com",
		"tls_settings": {"server_name": "edge.example.com"},
		"base_config": {"push_interval": 60, "pull_interval": 60}
	}`
	calls := 0
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return textResponse(r, http.StatusOK, body), nil
	}))

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("first GetNodeInfo failed: %v", err)
	}
	if node == nil {
		t.Fatal("first GetNodeInfo returned no node")
	}

	node, err = client.GetNodeInfo()
	if err != nil {
		t.Fatalf("second GetNodeInfo failed: %v", err)
	}
	if node != nil {
		t.Fatal("unchanged config should short-circuit on the body hash")
	}

	client.InvalidateNodeInfoCache()

	node, err = client.GetNodeInfo()
	if err != nil {
		t.Fatalf("third GetNodeInfo failed: %v", err)
	}
	if node == nil {
		t.Fatal("invalidating the cache must make the same config reload again")
	}
	if calls != 3 {
		t.Fatalf("expected 3 panel round trips, got %d", calls)
	}
}
