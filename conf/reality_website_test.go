package conf

import (
	"testing"
)

func TestRealityWebsiteConfig(t *testing.T) {
	for _, tc := range []struct {
		name, core, domain string
		port               int
		nested             bool
	}{
		{"flat", "xray", "site.example", 8443, false},
		{"auto", "", "site.example", 9443, true},
		{"sing", "sing", "site.example", 8443, true},
		{"wildcard", "xray", "*.example", 8443, true},
		{"missing_name", "xray", "", 8443, true},
		{"missing_port", "xray", "site.example", 0, false},
		{"out_of_range", "xray", "site.example", 65536, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := validDoc()
			if tc.core == "sing" {
				docCore(doc, 0)["Type"] = "sing"
			}
			node := docNode(doc, 0)
			options := node
			if tc.nested {
				delete(node, "Core")
				options = map[string]any{}
				node["Options"] = options
			}
			options["Core"] = tc.core
			options["RealityWebsite"] = map[string]any{"ServerName": tc.domain, "Port": tc.port, "ProxyProtocol": true}
			cfg, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.NodeConfig[0].Options.RealityWebsite
			if got == nil || got.ServerName != tc.domain || int(got.Port) != tc.port || !got.ProxyProtocol {
				t.Fatalf("wrong website settings: %+v", got)
			}
		})
	}
}
