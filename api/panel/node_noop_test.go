package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

const unchangedNodeBody = `{"server_port":443,"network":"tcp","base_config":{"pull_interval":60,"push_interval":60}}`

func noopPanelClient(t *testing.T, transport roundTripFunc) *Client {
	t.Helper()
	c, err := New(&conf.ApiConfig{APIHost: "http://panel.test", Key: "token", NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.client.SetTransport(transport)
	return c
}

func TestSyncConfigDoesNotRebuildUnchangedNode(t *testing.T) {
	calls := 0
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 && r.Header.Get("If-None-Match") != "" {
			t.Fatal("sync.config did not force a fresh fetch")
		}
		if calls == 3 && r.Header.Get("If-None-Match") != `"new"` {
			t.Fatal("no-op response did not update ETag")
		}
		rsp := textResponse(r, http.StatusOK, unchangedNodeBody)
		rsp.Header.Set("ETag", `"new"`)
		return rsp, nil
	})
	if node, err := c.GetNodeInfo(); err != nil || node == nil {
		t.Fatalf("initial config: node=%v err=%v", node, err)
	}
	driver := &wsDriver{cfg: wsDriverConfig{Hooks: wsDriverHooks{OnSyncConfig: c.invalidateNodeInfoCache}}}
	if err := driver.handleMessage([]byte(`{"event":"sync.config"}`)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if node, err := c.GetNodeInfo(); err != nil || node != nil {
			t.Fatalf("unchanged config would rebuild node: node=%v err=%v", node, err)
		}
	}
}

func TestNodeConfigIgnoresFormattingButAppliesRealChanges(t *testing.T) {
	body := unchangedNodeBody
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		return textResponse(r, http.StatusOK, body), nil
	})
	if node, err := c.GetNodeInfo(); err != nil || node == nil {
		t.Fatalf("initial config: %v", err)
	}
	body = "{\n\"base_config\": {\"push_interval\":60, \"pull_interval\":60}, \"network\":\"tcp\", \"server_port\":443}"
	if node, err := c.GetNodeInfo(); err != nil || node != nil {
		t.Fatalf("formatting changed node: node=%v err=%v", node, err)
	}
	body = `{"server_port":443,"network":"tcp","base_config":{"pull_interval":60,"push_interval":60},"updated_at":"changed metadata"}`
	if node, err := c.GetNodeInfo(); err != nil || node != nil {
		t.Fatalf("ignored panel metadata changed node: node=%v err=%v", node, err)
	}
	body = `{"server_port":8443,"network":"tcp","base_config":{"pull_interval":60,"push_interval":60}}`
	if node, err := c.GetNodeInfo(); err != nil || node == nil || node.Common.ServerPort != 8443 {
		t.Fatalf("real change lost: node=%v err=%v", node, err)
	}
}

func TestNodeConfigDecodeFailureIsNotCached(t *testing.T) {
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		return textResponse(r, http.StatusOK, `{"server_port":"invalid"}`), nil
	})
	for range 2 {
		if _, err := c.GetNodeInfo(); err == nil {
			t.Fatal("an invalid response was cached as an unchanged config")
		}
	}
}

func TestNodeConfigInFlightResponsePreservesForcedRetry(t *testing.T) {
	var invalidate func()
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		if invalidate != nil {
			invalidate()
			invalidate = nil
		}
		rsp := textResponse(r, http.StatusOK, unchangedNodeBody)
		rsp.Header.Set("ETag", `"stale"`)
		return rsp, nil
	})
	if _, err := c.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	invalidate = c.InvalidateNodeInfoCache
	if _, err := c.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	if c.nodeEtag != "" || c.nodeConfigHash != "" {
		t.Fatal("an in-flight response erased the forced retry")
	}
	if node, err := c.GetNodeInfo(); err != nil || node == nil {
		t.Fatalf("forced rebuild lost: node=%v err=%v", node, err)
	}
}

func TestNodeConfigInFlightPushDoesNotRepeatAppliedChange(t *testing.T) {
	var invalidate func()
	body := unchangedNodeBody
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		if invalidate != nil {
			invalidate()
			invalidate = nil
		}
		rsp := textResponse(r, http.StatusOK, body)
		rsp.Header.Set("ETag", `"in-flight"`)
		return rsp, nil
	})
	if node, err := c.GetNodeInfo(); err != nil || node == nil {
		t.Fatalf("initial node: %v", err)
	}
	body = `{"server_port":8443,"network":"tcp","base_config":{"pull_interval":60,"push_interval":60}}`
	invalidate = c.invalidateNodeInfoCache
	if node, err := c.GetNodeInfo(); err != nil || node == nil {
		t.Fatalf("real change: %v", err)
	}
	if c.nodeEtag != "" {
		t.Fatal("in-flight push was overwritten by a stale ETag")
	}
	if node, err := c.GetNodeInfo(); err != nil || node != nil {
		t.Fatalf("already applied change was returned again: node=%v err=%v", node, err)
	}
}
