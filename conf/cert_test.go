package conf

import (
	"encoding/json"
	"testing"
)

func TestCertConfigUnmarshalAcceptsXBoardSnakeCase(t *testing.T) {
	raw := []byte(`{
		"cert_mode": "dns",
		"reject_unknown_sni": true,
		"cert_domain": "edge.example.com",
		"cert_file": "/etc/n2x/cert.pem",
		"key_file": "/etc/n2x/key.pem",
		"provider": "cloudflare",
		"email": "ops@example.com",
		"dns_env": {
			"CF_DNS_API_TOKEN": "token"
		}
	}`)

	var config CertConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal cert config failed: %v", err)
	}

	if config.CertMode != "dns" {
		t.Fatalf("expected cert mode dns, got %q", config.CertMode)
	}
	if !config.RejectUnknownSni {
		t.Fatal("expected reject unknown sni to be true")
	}
	if config.CertDomain != "edge.example.com" {
		t.Fatalf("expected cert domain to be parsed, got %q", config.CertDomain)
	}
	if config.CertFile != "/etc/n2x/cert.pem" {
		t.Fatalf("expected cert file to be parsed, got %q", config.CertFile)
	}
	if config.KeyFile != "/etc/n2x/key.pem" {
		t.Fatalf("expected key file to be parsed, got %q", config.KeyFile)
	}
	if config.Provider != "cloudflare" {
		t.Fatalf("expected provider to be parsed, got %q", config.Provider)
	}
	if config.Email != "ops@example.com" {
		t.Fatalf("expected email to be parsed, got %q", config.Email)
	}
	if config.DNSEnv["CF_DNS_API_TOKEN"] != "token" {
		t.Fatalf("expected dns env to be parsed, got %+v", config.DNSEnv)
	}
}

func TestCertConfigUnmarshalAcceptsLegacyCamelCase(t *testing.T) {
	raw := []byte(`{
		"CertMode": "file",
		"RejectUnknownSni": true,
		"CertDomain": "legacy.example.com",
		"CertFile": "/legacy/cert.pem",
		"KeyFile": "/legacy/key.pem",
		"Provider": "alidns",
		"Email": "legacy@example.com",
		"DNSEnv": {
			"ALICLOUD_ACCESS_KEY": "key"
		}
	}`)

	var config CertConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal cert config failed: %v", err)
	}

	if config.CertMode != "file" {
		t.Fatalf("expected cert mode file, got %q", config.CertMode)
	}
	if config.CertDomain != "legacy.example.com" {
		t.Fatalf("expected legacy cert domain to be parsed, got %q", config.CertDomain)
	}
	if config.CertFile != "/legacy/cert.pem" || config.KeyFile != "/legacy/key.pem" {
		t.Fatalf("expected legacy cert files to be parsed, got cert=%q key=%q", config.CertFile, config.KeyFile)
	}
	if config.Provider != "alidns" || config.Email != "legacy@example.com" {
		t.Fatalf("expected legacy acme fields to be parsed, got provider=%q email=%q", config.Provider, config.Email)
	}
	if config.DNSEnv["ALICLOUD_ACCESS_KEY"] != "key" {
		t.Fatalf("expected legacy dns env to be parsed, got %+v", config.DNSEnv)
	}
}

func TestCertConfigUnmarshalAcceptsModeAlias(t *testing.T) {
	raw := []byte(`{"mode":"file","cert_file":"/panel/cert.pem","key_file":"/panel/key.pem"}`)

	var config CertConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal cert config failed: %v", err)
	}

	if config.CertMode != "file" {
		t.Fatalf("expected mode alias to populate cert mode, got %q", config.CertMode)
	}
}

func TestCertConfigUnmarshalDerivesManagedPathsFromDomain(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		certFile string
		keyFile  string
	}{
		{
			name:     "legacy defaults",
			raw:      `{"CertMode":"dns","CertDomain":"new.example.com","CertFile":"/etc/N2X/fullchain.cer","KeyFile":"/etc/N2X/cert.key"}`,
			certFile: "/etc/N2X/fullchain-new.example.com.cer",
			keyFile:  "/etc/N2X/cert-new.example.com.key",
		},
		{
			name:     "previous managed domain",
			raw:      `{"cert_mode":"http","cert_domain":"new.example.com","cert_file":"/etc/N2X/fullchain-old.example.com.cer","key_file":"/etc/N2X/cert-old.example.com.key"}`,
			certFile: "/etc/N2X/fullchain-new.example.com.cer",
			keyFile:  "/etc/N2X/cert-new.example.com.key",
		},
		{
			name:     "domain placeholders",
			raw:      `{"CertMode":"self","CertDomain":"new.example.com","CertFile":"/etc/N2X/fullchain-{domain}.cer","KeyFile":"/etc/N2X/cert-{domain}.key"}`,
			certFile: "/etc/N2X/fullchain-new.example.com.cer",
			keyFile:  "/etc/N2X/cert-new.example.com.key",
		},
		{
			name:     "wildcard domain",
			raw:      `{"CertMode":"dns","CertDomain":"*.example.com","CertFile":"/etc/N2X/fullchain.cer","KeyFile":"/etc/N2X/cert.key"}`,
			certFile: "/etc/N2X/fullchain-wildcard.example.com.cer",
			keyFile:  "/etc/N2X/cert-wildcard.example.com.key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config CertConfig
			if err := json.Unmarshal([]byte(test.raw), &config); err != nil {
				t.Fatalf("unmarshal cert config failed: %v", err)
			}
			if config.CertFile != test.certFile || config.KeyFile != test.keyFile {
				t.Fatalf("expected cert=%q key=%q, got cert=%q key=%q", test.certFile, test.keyFile, config.CertFile, config.KeyFile)
			}
		})
	}
}

func TestCertConfigUnmarshalPreservesExplicitPaths(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "automatic mode custom paths",
			raw:  `{"CertMode":"dns","CertDomain":"new.example.com","CertFile":"/custom/server.pem","KeyFile":"/custom/server.key"}`,
		},
		{
			name: "file mode legacy paths",
			raw:  `{"CertMode":"file","CertDomain":"new.example.com","CertFile":"/etc/N2X/fullchain.cer","KeyFile":"/etc/N2X/cert.key"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var expected map[string]any
			if err := json.Unmarshal([]byte(test.raw), &expected); err != nil {
				t.Fatalf("unmarshal expected config failed: %v", err)
			}

			var config CertConfig
			if err := json.Unmarshal([]byte(test.raw), &config); err != nil {
				t.Fatalf("unmarshal cert config failed: %v", err)
			}
			if config.CertFile != expected["CertFile"] || config.KeyFile != expected["KeyFile"] {
				t.Fatalf("expected explicit paths to be preserved, got cert=%q key=%q", config.CertFile, config.KeyFile)
			}
		})
	}
}
