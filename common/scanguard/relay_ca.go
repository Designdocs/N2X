package scanguard

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"os"

	"github.com/Designdocs/N2X/conf"
)

//go:embed ddns-master-public.pem
var bundledRelayCA []byte

// HasRelayCA is independent of scan enforcement so disabling bans keeps authenticated routes online.
func HasRelayCA(cfg conf.WSScanGuardConfig) bool {
	return cfg.RelayCAFile != "" || (cfg.FeedbackCertFile != "" && cfg.FeedbackKeyFile != "")
}

func relayRoots(file string) (*x509.CertPool, error) {
	data := bundledRelayCA
	if file != "" && file != "builtin" {
		var err error
		data, err = os.ReadFile(file)
		if err != nil {
			return nil, err
		}
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one DDNS Master public CA certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || ca.PublicKeyAlgorithm != x509.Ed25519 || ca.CheckSignatureFrom(ca) != nil {
		return nil, errors.New("invalid DDNS Master public CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, nil
}
