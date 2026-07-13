package node

import (
	"os"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func newIntegrationTestLego(t *testing.T) *Lego {
	t.Helper()
	if os.Getenv("N2X_ACME_INTEGRATION") != "1" {
		t.Skip("set N2X_ACME_INTEGRATION=1 to run live ACME integration tests")
	}

	l, err := NewLego(&conf.CertConfig{
		CertMode:   "dns",
		Email:      "test@test.com",
		CertDomain: "test.test.com",
		Provider:   "cloudflare",
		DNSEnv: map[string]string{
			"CF_API_KEY":       "123",
			"CLOUDFLARE_EMAIL": "you@example.com",
		},
		CertFile: "./cert/1.pem",
		KeyFile:  "./cert/1.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLego_CreateCertByDns(t *testing.T) {
	l := newIntegrationTestLego(t)
	err := l.CreateCert()
	if err != nil {
		t.Error(err)
	}
}

func TestLego_RenewCert(t *testing.T) {
	l := newIntegrationTestLego(t)
	if err := l.RenewCert(); err != nil {
		t.Error(err)
	}
}
