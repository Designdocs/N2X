package panel

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"encoding/json"

	"github.com/Designdocs/N2X/conf"
)

func TestDecodeDeviceAliveMapFromSyncDevices(t *testing.T) {
	raw := json.RawMessage(`{
		"users": {
			"1": ["1.1.1.1:443", "1.1.1.1:8443", "[2001:db8::1]:443"],
			"2": ["2.2.2.2"],
			"bad": ["9.9.9.9"]
		},
		"node_id": 10
	}`)

	alive, err := decodeDeviceAliveMap(raw)
	if err != nil {
		t.Fatalf("decodeDeviceAliveMap() error = %v", err)
	}
	if got := alive[1]; got != 2 {
		t.Fatalf("alive[1] = %d, want 2", got)
	}
	if got := alive[2]; got != 1 {
		t.Fatalf("alive[2] = %d, want 1", got)
	}
	if _, ok := alive[0]; ok {
		t.Fatal("decoded invalid user id")
	}
}

func TestDecodeDeviceAliveMapAcceptsDevicesWrapper(t *testing.T) {
	raw := json.RawMessage(`{"devices":{"7":["7.7.7.7"],"8":2}}`)

	alive, err := decodeDeviceAliveMap(raw)
	if err != nil {
		t.Fatalf("decodeDeviceAliveMap() error = %v", err)
	}
	if got := alive[7]; got != 1 {
		t.Fatalf("alive[7] = %d, want 1", got)
	}
	if got := alive[8]; got != 2 {
		t.Fatalf("alive[8] = %d, want 2", got)
	}
}

func TestWSAuthSuccessMarksConnected(t *testing.T) {
	driver, err := newWSDriver(wsDriverConfig{
		URL:    "ws://127.0.0.1/ws/",
		NodeID: 1,
		Token:  "token",
	})
	if err != nil {
		t.Fatalf("newWSDriver() error = %v", err)
	}
	if driver.Connected() {
		t.Fatal("new driver should not be connected before auth.success")
	}
	if err := driver.handleMessage([]byte(`{"event":"auth.success","data":{"node_id":1}}`)); err != nil {
		t.Fatalf("handleMessage(auth.success) error = %v", err)
	}
	if !driver.Connected() {
		t.Fatal("driver should be connected after auth.success")
	}
}

func TestReportNodeOnlineUsersReturnsHTTPError(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "vless",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return textResponse(req, http.StatusInternalServerError, "failed"), nil
	}))

	data := map[int][]string{1: []string{"127.0.0.1"}}
	if err := client.ReportNodeOnlineUsers(&data); err == nil {
		t.Fatal("ReportNodeOnlineUsers() error = nil, want HTTP error")
	}
}

func TestGetNodeInfoHTTPErrorDoesNotPoisonCache(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://panel.test",
		Key:      "token",
		NodeType: "vless",
		NodeID:   1,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := textResponse(req, http.StatusInternalServerError, "failed")
		resp.Header.Set("ETag", `"bad"`)
		return resp, nil
	}))

	if _, err := client.GetNodeInfo(); err == nil {
		t.Fatal("GetNodeInfo() error = nil, want HTTP error")
	}
	if client.nodeEtag != "" {
		t.Fatalf("nodeEtag = %q, want empty", client.nodeEtag)
	}
	if client.responseBodyHash != "" {
		t.Fatalf("responseBodyHash = %q, want empty", client.responseBodyHash)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func textResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
