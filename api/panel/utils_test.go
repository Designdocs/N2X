package panel

import (
	"strings"
	"testing"
)

func TestAssembleURL(t *testing.T) {
	const path = "/api/v1/server/UniProxy/config"
	tests := []struct {
		name    string
		apiHost string
		want    string
	}{
		{
			name:    "host with port",
			apiHost: "http://127.0.0.1:1",
			want:    "http://127.0.0.1:1/api/v1/server/UniProxy/config",
		},
		{
			name:    "trailing slash",
			apiHost: "https://panel.example.com/",
			want:    "https://panel.example.com/api/v1/server/UniProxy/config",
		},
		{
			name:    "sub path",
			apiHost: "https://panel.example.com/sub/",
			want:    "https://panel.example.com/sub/api/v1/server/UniProxy/config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{APIHost: tt.apiHost}
			if got := c.assembleURL(path); got != tt.want {
				t.Errorf("assembleURL(%q) with ApiHost %q = %q, want %q", path, tt.apiHost, got, tt.want)
			}
		})
	}
}

func TestCheckResponseErrorKeepsSchemeSlashes(t *testing.T) {
	captureLog(t)
	host := unreachableHost(t)
	c := newRedactTestClient(t, host)

	_, err := c.GetNodeInfo()
	if err == nil {
		t.Fatal("want an error from an unreachable panel")
	}
	want := "request " + host + "/api/v1/server/UniProxy/config failed"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %v, want it to contain %q", err, want)
	}
}
