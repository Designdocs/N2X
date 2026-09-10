package panel

import (
	"github.com/Designdocs/N2X/conf"
	"net/http"
	"testing"
)

func TestGetNodeInfoDecoyFallback(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan"} {
		for _, value := range []string{"", "true", "false", "null", `"true"`} {
			t.Run(protocol+"/"+value, func(t *testing.T) {
				client, err := New(&conf.ApiConfig{APIHost: "http://panel.test", Key: "token", NodeType: protocol, NodeID: 1})
				if err != nil {
					t.Fatal(err)
				}
				body := `{"server_port":443,"network":"xhttp","base_config":{"push_interval":60,"pull_interval":60}`
				if value != "" {
					body += `,"decoy_fallback":` + value
				}
				body += "}"
				client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) { return textResponse(r, http.StatusOK, body), nil }))
				node, err := client.GetNodeInfo()
				if value == `"true"` {
					if err == nil {
						t.Fatal("accepted non-boolean switch")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if value == "" || value == "null" {
					if node.Common.DecoyFallback != nil {
						t.Fatal("missing switch must preserve local configuration")
					}
				} else if node.Common.DecoyFallback == nil || *node.Common.DecoyFallback != (value == "true") {
					t.Fatal("lost explicit panel switch")
				}
			})
		}
	}
}
