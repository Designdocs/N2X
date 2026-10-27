package conf

import (
	"strings"
	"testing"
)

func TestDDNSDefaultDisabledAndConfigSchema(t *testing.T) {
	doc := validDoc()
	loaded, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NodeConfig[0].Options.DDNSConfig.Enabled {
		t.Fatal("DDNS enabled by default")
	}
	docNode(doc, 0)["DDNSConfig"] = map[string]any{"Enabled": false, "Provider": "future-provider"}
	if _, err := LoadValidated(writeDoc(t, doc), ValidateOptions{}); err != nil {
		t.Fatal(err)
	}
	docNode(doc, 0)["DDNSConfig"] = map[string]any{"Enabled": true, "Provider": "other"}
	_, err = LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].DDNSConfig", "Provider")
	docNode(doc, 0)["DDNSConfig"] = map[string]any{"Enabled": false, "Enabeld": true}
	_, err = LoadValidated(writeDoc(t, doc), ValidateOptions{})
	assertIssue(t, err, "Nodes[0].DDNSConfig.Enabeld", "unknown key")
}

func TestDDNSCertificateFallbackAndSeparateCredentials(t *testing.T) {
	cert := &CertConfig{Provider: "cloudflare", CertDomain: "edge.example.co.uk",
		DNSEnv: map[string]string{"CF_DNS_API_TOKEN": "cert-token"}}
	c := (DDNSConfig{Enabled: true}).Effective(cert)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.ZoneName != "example.co.uk" || c.Domain != cert.CertDomain || c.DNSEnv["CF_DNS_API_TOKEN"] != "cert-token" {
		t.Fatalf("certificate fallback failed: domain=%s zone=%s", c.Domain, c.ZoneName)
	}
	independent := (DDNSConfig{Enabled: true, Provider: "alidns", Domain: "host.other.example",
		DNSEnv: map[string]string{"ALICLOUD_ACCESS_KEY": "ddns-key", "ALICLOUD_SECRET_KEY": "ddns-secret"}}).Effective(cert)
	if err := independent.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, ok := independent.DNSEnv["CF_DNS_API_TOKEN"]; ok {
		t.Fatal("mixed credentials between providers")
	}
	if cert.CertDomain != "edge.example.co.uk" {
		t.Fatal("certificate was mutated")
	}
}

func TestDDNSRejectsUnsafeOrIncompleteEnabledConfig(t *testing.T) {
	base := DDNSConfig{Enabled: true, Provider: "cloudflare", Domain: "edge.example.com",
		DNSEnv: map[string]string{"CF_DNS_API_TOKEN": "token"}}
	tests := []struct {
		name   string
		change func(*DDNSConfig)
		want   string
	}{
		{"wildcard", func(c *DDNSConfig) { c.Domain = "*.example.com" }, "Domain"},
		{"wrong zone", func(c *DDNSConfig) { c.ZoneName = "other.com" }, "inside ZoneName"},
		{"record type", func(c *DDNSConfig) { c.RecordType = "TXT" }, "RecordType"},
		{"fast interval", func(c *DDNSConfig) { c.Interval = 1 }, "Interval"},
		{"negative interval", func(c *DDNSConfig) { c.Interval = -1 }, "Interval"},
		{"ttl", func(c *DDNSConfig) { c.TTL = 2 }, "TTL"},
		{"plaintext IP URL", func(c *DDNSConfig) { c.IPURL = "http://example.com" }, "IPURL"},
		{"missing token", func(c *DDNSConfig) { c.DNSEnv = nil }, "CF_DNS_API_TOKEN"},
		{"global key", func(c *DDNSConfig) { c.DNSEnv = map[string]string{"CF_API_KEY": "global"} }, "CF_DNS_API_TOKEN"},
		{"ali credentials", func(c *DDNSConfig) { c.Provider = "alidns" }, "ALICLOUD_ACCESS_KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			tt.change(&c)
			err := c.Effective(nil).Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %s", err, tt.want)
			}
		})
	}
}
