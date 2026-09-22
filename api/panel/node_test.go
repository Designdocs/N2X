package panel

import (
	"log"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

var client *Client

func init() {
	c, err := New(&conf.ApiConfig{
		APIHost:  "http://127.0.0.1",
		Key:      "token",
		NodeType: "V2ray",
		NodeID:   1,
	})
	if err != nil {
		log.Panic(err)
	}
	client = c
}

func TestClient_GetNodeInfo(t *testing.T) {
	log.Println(client.GetNodeInfo())
	log.Println(client.GetNodeInfo())
}

func TestClient_ReportUserTraffic(t *testing.T) {
	log.Println(client.ReportUserTraffic([]UserTraffic{
		{
			UID:      10372,
			Upload:   1000,
			Download: 1000,
		},
	}))
}

func TestIgnoredIPsToListDecodesLeniently(t *testing.T) {
	cases := map[string]struct {
		in   interface{}
		want []string
	}{
		"absent":     {nil, []string{}},
		"array":      {[]interface{}{"56.69.64.164/32", " 43.216.0.0/16 ", "", 7}, []string{"56.69.64.164/32", "43.216.0.0/16"}},
		"string":     {"1.2.3.4/32, 5.6.7.8/32\n9.9.9.9/32", []string{"1.2.3.4/32", "5.6.7.8/32", "9.9.9.9/32"}},
		"wrong type": {42.0, []string{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := ignoredIPsToList(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}
