package xray

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

func TestBuildInboundTLSConfig_MapsAnyTLSECHServerKeys(t *testing.T) {
	echKeyBytes := []byte{0x01, 0x02, 0x03, 0x04}
	echKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: echKeyBytes}))
	echConfigPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: []byte{0x05, 0x06}}))

	option := &conf.Options{
		XrayOptions: conf.NewXrayOptions(),
		CertConfig: &conf.CertConfig{
			CertMode:         "file",
			RejectUnknownSni: true,
			CertFile:         "/tmp/cert.pem",
			KeyFile:          "/tmp/key.pem",
		},
	}
	nodeInfo := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		AnyTls: &panel.AnyTlsNode{
			TlsSettings: panel.TlsSettings{
				Ech: &panel.ECHSettings{
					Enabled: true,
					Config:  echConfigPEM,
					Key:     echKeyPEM,
				},
			},
		},
	}

	tlsConfig, err := buildInboundTLSConfig(option, nodeInfo)
	if err != nil {
		t.Fatalf("buildInboundTLSConfig returned error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected tls config to be created")
	}

	expectedKey := base64.StdEncoding.EncodeToString(echKeyBytes)
	if tlsConfig.ECHServerKeys != expectedKey {
		t.Fatalf("expected ECH server keys %q, got %q", expectedKey, tlsConfig.ECHServerKeys)
	}
	if len(tlsConfig.Certs) != 1 {
		t.Fatalf("expected one certificate entry, got %d", len(tlsConfig.Certs))
	}
	if !tlsConfig.RejectUnknownSNI {
		t.Fatal("expected reject unknown sni to be preserved")
	}
}

func TestBuildInboundTLSConfigPrefersPanelCertConfig(t *testing.T) {
	option := &conf.Options{
		XrayOptions: conf.NewXrayOptions(),
		CertConfig: &conf.CertConfig{
			CertMode: "none",
		},
	}
	nodeInfo := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		CertConfig: &conf.CertConfig{
			CertMode:         "file",
			RejectUnknownSni: true,
			CertFile:         "/panel/cert.pem",
			KeyFile:          "/panel/key.pem",
		},
		AnyTls: &panel.AnyTlsNode{},
	}

	tlsConfig, err := buildInboundTLSConfig(option, nodeInfo)
	if err != nil {
		t.Fatalf("buildInboundTLSConfig returned error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected tls config from panel cert_config")
	}
	if len(tlsConfig.Certs) != 1 {
		t.Fatalf("expected one certificate entry, got %d", len(tlsConfig.Certs))
	}
	cert := tlsConfig.Certs[0]
	if cert.CertFile != "/panel/cert.pem" || cert.KeyFile != "/panel/key.pem" {
		t.Fatalf("expected panel cert files, got cert=%q key=%q", cert.CertFile, cert.KeyFile)
	}
	if !tlsConfig.RejectUnknownSNI {
		t.Fatal("expected panel reject_unknown_sni to be applied")
	}
}

func TestBuildInboundTLSConfigRejectsECHConfigWithoutServerKey(t *testing.T) {
	echConfigPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: []byte{0x01}}))
	option := &conf.Options{
		XrayOptions: conf.NewXrayOptions(),
		CertConfig: &conf.CertConfig{
			CertMode: "file",
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}
	nodeInfo := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		AnyTls: &panel.AnyTlsNode{
			TlsSettings: panel.TlsSettings{
				Ech: &panel.ECHSettings{
					Enabled: true,
					Config:  echConfigPEM,
				},
			},
		},
	}

	if _, err := buildInboundTLSConfig(option, nodeInfo); err == nil {
		t.Fatal("expected missing ECH server key to be rejected")
	}
}

func TestBuildInboundTLSConfigRejectsECHServerKeyWithoutClientConfig(t *testing.T) {
	echKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: []byte{0x01}}))
	option := &conf.Options{
		XrayOptions: conf.NewXrayOptions(),
		CertConfig: &conf.CertConfig{
			CertMode: "file",
			CertFile: "/tmp/cert.pem",
			KeyFile:  "/tmp/key.pem",
		},
	}
	nodeInfo := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		AnyTls: &panel.AnyTlsNode{
			TlsSettings: panel.TlsSettings{
				Ech: &panel.ECHSettings{
					Enabled: true,
					Key:     echKeyPEM,
				},
			},
		},
	}

	if _, err := buildInboundTLSConfig(option, nodeInfo); err == nil {
		t.Fatal("expected missing ECH client config to be rejected")
	}
}

func TestNormalizeECHValue_RejectsUnexpectedPEMType(t *testing.T) {
	invalidPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: []byte{0x01}}))

	if _, err := normalizeECHValue(invalidPEM, "ECH KEYS"); err == nil {
		t.Fatal("expected normalizeECHValue to reject unexpected pem type")
	}
}
