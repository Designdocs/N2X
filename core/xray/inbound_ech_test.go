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

func TestNormalizeECHValue_RejectsUnexpectedPEMType(t *testing.T) {
	invalidPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: []byte{0x01}}))

	if _, err := normalizeECHValue(invalidPEM, "ECH KEYS"); err == nil {
		t.Fatal("expected normalizeECHValue to reject unexpected pem type")
	}
}
