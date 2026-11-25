package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestRealityWebsiteRequestsNodeAddress(t *testing.T) {
	client, err := New(&conf.ApiConfig{APIHost: "http://panel.test", Key: "token", NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-N2X-Reality-Host") != "1" {
			t.Error("missing node address capability")
		}
		return textResponse(r, http.StatusOK, `{"tls":2,"network":"tcp","server_port":443,"host":"website.example","tls_settings":{"server_name":"reality.example"},"base_config":{"push_interval":60,"pull_interval":60}}`), nil
	}))
	info, err := client.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.Common.Host != "website.example" || info.VAllss.TlsSettings.ServerName != "reality.example" {
		t.Fatal("lost the separate website and REALITY names")
	}
}
