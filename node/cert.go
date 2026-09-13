package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/file"
	"github.com/Designdocs/N2X/conf"
	"github.com/go-acme/lego/v4/certcrypto"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) effectiveCertConfig(node *panel.NodeInfo) *conf.CertConfig {
	if node != nil && node.CertConfig != nil && node.CertConfig.CertMode != "" {
		return node.CertConfig
	}
	if c.Options == nil {
		return nil
	}
	return c.CertConfig
}

func (c *Controller) renewCertTask(certConfig *conf.CertConfig) error {
	if certConfig == nil || (certConfig.CertMode != "dns" && certConfig.CertMode != "http") {
		return nil
	}
	// Checked before anything else so the daily tick stays offline (no
	// account load, no DNS self-test record) until renewal is actually due.
	due, err := certRenewalDue(certConfig.CertFile, time.Now())
	if err != nil {
		log.WithField("tag", c.tag).Warn("check cert expiry error: ", err)
		return nil
	}
	if !due {
		return nil
	}
	if err := placeCertOrder(certConfig, renewIssuedCert); err != nil {
		log.WithField("tag", c.tag).Error("renew cert error: ", err)
		return nil
	}
	c.refreshHTTPSRedirect(c.info)
	return nil
}

func (c *Controller) requestCert(node *panel.NodeInfo) error {
	certConfig := c.effectiveCertConfig(node)
	if certConfig == nil {
		return fmt.Errorf("cert config not exist")
	}

	switch certConfig.CertMode {
	case "none", "":
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		// Checked here so the error names the missing file instead of
		// surfacing later as an opaque core TLS build failure.
		for _, path := range []string{certConfig.CertFile, certConfig.KeyFile} {
			if !file.IsExist(path) {
				return fmt.Errorf("cert file not found: %s", path)
			}
		}
	case "dns", "http":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(certConfig.CertFile) && file.IsExist(certConfig.KeyFile) {
			return nil
		}
		return obtainCert(certConfig)
	case "self":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(certConfig.CertFile) && file.IsExist(certConfig.KeyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			certConfig.CertDomain,
			certConfig.CertFile,
			certConfig.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
	return nil
}

// Swapped by tests so the order flow can be exercised without a CA.
var (
	issueCert       = createCert
	renewIssuedCert = renewCert
)

func obtainCert(certConfig *conf.CertConfig) error {
	return placeCertOrder(certConfig, issueCert)
}

// placeCertOrder runs an ACME order only once nothing local stands in its
// way: the config must be valid, no identical order may be cooling down, and
// the self-test must pass. Only a failure of the order itself starts a
// cooldown, so fixing a config or self-test problem lets the next attempt go
// straight through.
func placeCertOrder(certConfig *conf.CertConfig, order func(*conf.CertConfig) error) error {
	if err := validateCertConfig(certConfig); err != nil {
		return err
	}
	key := certOrderCooldownKey(certConfig)
	if err := certOrders.Check(key); err != nil {
		return fmt.Errorf("request cert for %s: %w", certConfig.CertDomain, err)
	}
	if err := runCertPreflight(certConfig); err != nil {
		return err
	}
	if err := order(certConfig); err != nil {
		err = redactDNSEnv(err, certConfig.DNSEnv)
		certOrders.RecordFailure(key, err)
		return err
	}
	certOrders.RecordSuccess(key)
	return nil
}

func createCert(certConfig *conf.CertConfig) error {
	l, err := NewLego(certConfig)
	if err != nil {
		return fmt.Errorf("create lego object error: %w", err)
	}
	if err := l.CreateCert(); err != nil {
		return fmt.Errorf("create lego cert error: %w", err)
	}
	return nil
}

func renewCert(certConfig *conf.CertConfig) error {
	l, err := NewLego(certConfig)
	if err != nil {
		return fmt.Errorf("create lego object error: %w", err)
	}
	if err := l.RenewCert(); err != nil {
		return fmt.Errorf("renew lego cert error: %w", err)
	}
	return nil
}

const certRenewWindow = 31 * 24 * time.Hour

// certRenewalDue reports whether the certificate at certFile has entered the
// renewal window (30 whole days or fewer left, as Lego.CheckCert counts).
func certRenewalDue(certFile string, now time.Time) (bool, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return false, fmt.Errorf("read cert file: %w", err)
	}
	cert, err := certcrypto.ParsePEMCertificate(certPEM)
	if err != nil {
		return false, fmt.Errorf("parse cert file %s: %w", certFile, err)
	}
	return cert.NotAfter.Sub(now) < certRenewWindow, nil
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	return nil
}
