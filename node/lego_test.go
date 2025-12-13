package node

import (
	"log"
	"os"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

var l *Lego

func init() {
	var err error
	l, err = NewLego(&conf.CertConfig{
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
		log.Println(err)
		os.Exit(1)
	}
}

func TestLego_CreateCertByDns(t *testing.T) {
	err := l.CreateCert()
	if err != nil {
		t.Error(err)
	}
}

func TestLego_RenewCert(t *testing.T) {
	log.Println(l.RenewCert())
}
