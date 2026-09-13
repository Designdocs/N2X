package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/go-acme/lego/v4/challenge"
)

func validDNSCertConfig(t *testing.T) *conf.CertConfig {
	t.Helper()
	directory := t.TempDir()
	return &conf.CertConfig{
		CertMode:   "dns",
		CertDomain: "us.example.com",
		CertFile:   filepath.Join(directory, "fullchain-us.example.com.cer"),
		KeyFile:    filepath.Join(directory, "cert-us.example.com.key"),
		Provider:   "cloudflare",
		Email:      "ops@example.com",
		DNSEnv:     map[string]string{"CF_DNS_API_TOKEN": "token"},
	}
}

func assertCertCheckStage(t *testing.T, err error, stage certCheckStage) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", stage)
	}
	var checkErr *certCheckError
	if !errors.As(err, &checkErr) {
		t.Fatalf("expected *certCheckError, got %T: %v", err, err)
	}
	if checkErr.Stage != stage {
		t.Fatalf("expected stage %s, got %s: %v", stage, checkErr.Stage, err)
	}
}

func TestValidateCertConfigRejectsBrokenConfigs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*conf.CertConfig)
		want   string
	}{
		{"empty domain", func(c *conf.CertConfig) { c.CertDomain = "" }, "domain"},
		{"domain with scheme", func(c *conf.CertConfig) { c.CertDomain = "https://us.example.com" }, "https://us.example.com"},
		{"domain with port", func(c *conf.CertConfig) { c.CertDomain = "us.example.com:443" }, "us.example.com:443"},
		{"domain with path", func(c *conf.CertConfig) { c.CertDomain = "us.example.com/x" }, "us.example.com/x"},
		{"domain with space", func(c *conf.CertConfig) { c.CertDomain = "us example.com" }, "us example.com"},
		{"ip address", func(c *conf.CertConfig) { c.CertDomain = "203.0.113.7" }, "IP"},
		{"single label", func(c *conf.CertConfig) { c.CertDomain = "localhost" }, "localhost"},
		{"underscore label", func(c *conf.CertConfig) { c.CertDomain = "us_1.example.com" }, "us_1.example.com"},
		{"leading hyphen", func(c *conf.CertConfig) { c.CertDomain = "-us.example.com" }, "-us.example.com"},
		{"empty label", func(c *conf.CertConfig) { c.CertDomain = "us..example.com" }, "us..example.com"},
		{"nested wildcard", func(c *conf.CertConfig) { c.CertDomain = "*.*.example.com" }, "wildcard"},
		{"inner wildcard", func(c *conf.CertConfig) { c.CertDomain = "us.*.example.com" }, "wildcard"},
		{"wildcard over http", func(c *conf.CertConfig) {
			c.CertMode = "http"
			c.CertDomain = "*.example.com"
		}, "wildcard"},
		{"bad email", func(c *conf.CertConfig) { c.Email = "ops@" }, "ops@"},
		{"email with display name", func(c *conf.CertConfig) { c.Email = "Ops <ops@example.com>" }, "email"},
		{"missing provider", func(c *conf.CertConfig) { c.Provider = "" }, "provider"},
		{"interactive provider", func(c *conf.CertConfig) { c.Provider = "manual" }, "manual"},
		{"empty dns env value", func(c *conf.CertConfig) { c.DNSEnv = map[string]string{"CF_DNS_API_TOKEN": " "} }, "CF_DNS_API_TOKEN"},
		{"same cert and key path", func(c *conf.CertConfig) { c.KeyFile = c.CertFile }, "same"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certConfig := validDNSCertConfig(t)
			tt.mutate(certConfig)
			err := validateCertConfig(certConfig)
			assertCertCheckStage(t, err, certCheckConfig)
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error to mention %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateCertConfigAcceptsValidConfigs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*conf.CertConfig)
	}{
		{"dns", func(*conf.CertConfig) {}},
		{"dns wildcard", func(c *conf.CertConfig) { c.CertDomain = "*.example.com" }},
		{"mixed case trailing dot", func(c *conf.CertConfig) { c.CertDomain = "US.Example.com." }},
		{"http multi level", func(c *conf.CertConfig) {
			c.CertMode = "http"
			c.CertDomain = "a-b.example.co.uk"
			c.Provider = ""
			c.DNSEnv = nil
		}},
		{"no email", func(c *conf.CertConfig) { c.Email = "" }},
		{"punycode", func(c *conf.CertConfig) { c.CertDomain = "xn--fiqs8s.example.com" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certConfig := validDNSCertConfig(t)
			tt.mutate(certConfig)
			if err := validateCertConfig(certConfig); err != nil {
				t.Fatalf("expected valid config, got %v", err)
			}
		})
	}
}

type recordingDNSProvider struct {
	presentErr error
	cleanUpErr error
	presented  []string
	cleaned    []string
}

func (p *recordingDNSProvider) Present(domain, token, _ string) error {
	p.presented = append(p.presented, domain+"|"+token)
	return p.presentErr
}

func (p *recordingDNSProvider) CleanUp(domain, token, _ string) error {
	p.cleaned = append(p.cleaned, domain+"|"+token)
	return p.cleanUpErr
}

func dnsPreflightWith(provider challenge.Provider, factoryErr error) *certPreflight {
	p := newCertPreflight()
	p.newDNSProvider = func(string, map[string]string) (challenge.Provider, error) {
		if factoryErr != nil {
			return nil, factoryErr
		}
		return provider, nil
	}
	return p
}

func TestCertPreflightDNSCreatesAndRemovesTestRecord(t *testing.T) {
	provider := &recordingDNSProvider{}
	certConfig := validDNSCertConfig(t)
	certConfig.CertDomain = "*.example.com"

	if err := dnsPreflightWith(provider, nil).Run(certConfig); err != nil {
		t.Fatalf("expected preflight to pass, got %v", err)
	}
	if len(provider.presented) != 1 || len(provider.cleaned) != 1 {
		t.Fatalf("expected one Present and one CleanUp, got %v / %v", provider.presented, provider.cleaned)
	}
	if provider.presented[0] != provider.cleaned[0] {
		t.Fatalf("expected CleanUp to remove the presented record, got %v / %v", provider.presented, provider.cleaned)
	}
	if !strings.HasPrefix(provider.presented[0], "example.com|") {
		t.Fatalf("expected wildcard to be tested on its base domain, got %s", provider.presented[0])
	}
}

func TestCertPreflightDNSReportsProviderFailures(t *testing.T) {
	t.Run("credentials rejected at construction", func(t *testing.T) {
		err := dnsPreflightWith(nil, errors.New("cloudflare: some credentials information are missing")).
			Run(validDNSCertConfig(t))
		assertCertCheckStage(t, err, certCheckConfig)
		if !strings.Contains(err.Error(), "credentials information are missing") {
			t.Fatalf("expected provider error in message, got %v", err)
		}
	})

	t.Run("zone not reachable", func(t *testing.T) {
		provider := &recordingDNSProvider{presentErr: errors.New("cloudflare: failed to find zone ccc-loc.com: zone could not be found")}
		err := dnsPreflightWith(provider, nil).Run(validDNSCertConfig(t))
		assertCertCheckStage(t, err, certCheckSelfTest)
		if !strings.Contains(err.Error(), "zone could not be found") {
			t.Fatalf("expected provider error in message, got %v", err)
		}
		if len(provider.cleaned) != 0 {
			t.Fatalf("expected no CleanUp after a failed Present, got %v", provider.cleaned)
		}
	})

	t.Run("record cannot be removed", func(t *testing.T) {
		provider := &recordingDNSProvider{cleanUpErr: errors.New("permission denied")}
		err := dnsPreflightWith(provider, nil).Run(validDNSCertConfig(t))
		assertCertCheckStage(t, err, certCheckSelfTest)
	})

	t.Run("credentials are redacted from provider errors", func(t *testing.T) {
		certConfig := validDNSCertConfig(t)
		certConfig.DNSEnv = map[string]string{"CF_DNS_API_TOKEN": "s3cr3t-token-value"}
		for name, preflight := range map[string]*certPreflight{
			"construction": dnsPreflightWith(nil, errors.New("invalid token s3cr3t-token-value")),
			"present":      dnsPreflightWith(&recordingDNSProvider{presentErr: errors.New("403 for s3cr3t-token-value")}, nil),
		} {
			err := preflight.Run(certConfig)
			if err == nil || strings.Contains(err.Error(), "s3cr3t-token-value") {
				t.Fatalf("%s: expected redacted error, got %v", name, err)
			}
		}
	})
}

type blockingDNSProvider struct {
	release chan struct{}
	cleaned chan struct{}
}

func (p *blockingDNSProvider) Present(string, string, string) error {
	<-p.release
	return nil
}

func (p *blockingDNSProvider) CleanUp(string, string, string) error {
	close(p.cleaned)
	return nil
}

func TestCertPreflightDNSTimesOutAndStillCleansUp(t *testing.T) {
	provider := &blockingDNSProvider{release: make(chan struct{}), cleaned: make(chan struct{})}
	preflight := dnsPreflightWith(provider, nil)
	preflight.dnsTimeout = 20 * time.Millisecond

	err := preflight.Run(validDNSCertConfig(t))
	assertCertCheckStage(t, err, certCheckSelfTest)
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}

	// A late Present must not leave the test record behind.
	close(provider.release)
	select {
	case <-provider.cleaned:
	case <-time.After(time.Second):
		t.Fatal("expected CleanUp after a Present that finished past the timeout")
	}
}

func TestRequestCertRedactsCredentialsFromOrderErrors(t *testing.T) {
	stubCertIssuance(t, nil, errors.New("acme: auth failed for s3cr3t-token-value"))
	certConfig := validDNSCertConfig(t)
	certConfig.DNSEnv = map[string]string{"CF_DNS_API_TOKEN": "s3cr3t-token-value"}

	err := obtainCert(certConfig)
	if err == nil || strings.Contains(err.Error(), "s3cr3t-token-value") {
		t.Fatalf("expected redacted order error, got %v", err)
	}
	if err := certOrders.Check(certOrderCooldownKey(certConfig)); err == nil ||
		strings.Contains(err.Error(), "s3cr3t-token-value") {
		t.Fatalf("expected redacted cooldown error, got %v", err)
	}
}

func TestCertPreflightChecksCertificateDirectoryIsWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	certConfig := validDNSCertConfig(t)
	certConfig.CertFile = filepath.Join(parent, "cert", "fullchain.cer")
	certConfig.KeyFile = filepath.Join(parent, "cert", "cert.key")

	provider := &recordingDNSProvider{}
	err := dnsPreflightWith(provider, nil).Run(certConfig)
	assertCertCheckStage(t, err, certCheckSelfTest)
	if !strings.Contains(err.Error(), filepath.Join(parent, "cert")) {
		t.Fatalf("expected error to name the directory, got %v", err)
	}
	if len(provider.presented) != 0 {
		t.Fatal("expected DNS self-test to be skipped when certificates cannot be saved")
	}
}

func TestCertPreflightLeavesNoFilesBehind(t *testing.T) {
	certConfig := validDNSCertConfig(t)
	directory := filepath.Join(t.TempDir(), "nested")
	certConfig.CertFile = filepath.Join(directory, "fullchain.cer")
	certConfig.KeyFile = filepath.Join(directory, "cert.key")

	if err := dnsPreflightWith(&recordingDNSProvider{}, nil).Run(certConfig); err != nil {
		t.Fatalf("expected preflight to pass, got %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("expected preflight to create the certificate directory: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatalf("expected no probe files left behind, found %s", entry.Name())
		}
	}
}

type closeTracker struct {
	net.Listener
	closed bool
}

func (l *closeTracker) Close() error {
	l.closed = true
	return nil
}

func httpCertConfig(t *testing.T) *conf.CertConfig {
	t.Helper()
	certConfig := validDNSCertConfig(t)
	certConfig.CertMode = "http"
	certConfig.Provider = ""
	certConfig.DNSEnv = nil
	return certConfig
}

func TestCertPreflightHTTP(t *testing.T) {
	t.Run("passes and releases port 80", func(t *testing.T) {
		listener := &closeTracker{}
		p := newCertPreflight()
		p.listen = func(network, address string) (net.Listener, error) {
			if address != ":80" {
				t.Fatalf("expected the HTTP-01 port, got %s", address)
			}
			return listener, nil
		}
		p.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		if err := p.Run(httpCertConfig(t)); err != nil {
			t.Fatalf("expected preflight to pass, got %v", err)
		}
		if !listener.closed {
			t.Fatal("expected the probe listener to be closed")
		}
	})

	t.Run("port 80 busy", func(t *testing.T) {
		p := newCertPreflight()
		p.listen = func(string, string) (net.Listener, error) {
			return nil, errors.New("bind: address already in use")
		}
		p.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		err := p.Run(httpCertConfig(t))
		assertCertCheckStage(t, err, certCheckSelfTest)
		if !strings.Contains(err.Error(), "80") {
			t.Fatalf("expected error to mention port 80, got %v", err)
		}
	})

	t.Run("domain does not resolve", func(t *testing.T) {
		p := newCertPreflight()
		p.listen = func(string, string) (net.Listener, error) { return &closeTracker{}, nil }
		p.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("no such host")
		}
		err := p.Run(httpCertConfig(t))
		assertCertCheckStage(t, err, certCheckSelfTest)
		if !strings.Contains(err.Error(), "us.example.com") {
			t.Fatalf("expected error to name the domain, got %v", err)
		}
	})
}

// stubCertIssuance swaps the preflight and the ACME call for the test and
// reports how many orders were placed.
func stubCertIssuance(t *testing.T, preflightErr, issueErr error) *int {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	previousOrders, previousPreflight, previousIssue := certOrders, runCertPreflight, issueCert
	t.Cleanup(func() {
		certOrders, runCertPreflight, issueCert = previousOrders, previousPreflight, previousIssue
	})

	certOrders = newCertOrderCooldown(clock.Now)
	runCertPreflight = func(*conf.CertConfig) error { return preflightErr }
	orders := 0
	issueCert = func(*conf.CertConfig) error {
		orders++
		return issueErr
	}
	return &orders
}

func TestRequestCertDoesNotOrderWithInvalidConfig(t *testing.T) {
	orders := stubCertIssuance(t, nil, nil)
	certConfig := validDNSCertConfig(t)
	certConfig.Provider = ""

	err := (&Controller{}).requestCert(&panel.NodeInfo{CertConfig: certConfig})
	assertCertCheckStage(t, err, certCheckConfig)
	if *orders != 0 {
		t.Fatalf("expected no ACME order, got %d", *orders)
	}
	if err := certOrders.Check(certOrderCooldownKey(certConfig)); err != nil {
		t.Fatalf("expected config errors not to start a cooldown, got %v", err)
	}
}

func TestRequestCertDoesNotOrderWhenSelfTestFails(t *testing.T) {
	orders := stubCertIssuance(t, &certCheckError{Stage: certCheckSelfTest, Err: errors.New("zone could not be found")}, nil)
	certConfig := validDNSCertConfig(t)
	controller := &Controller{}

	for range 3 {
		err := controller.requestCert(&panel.NodeInfo{CertConfig: certConfig})
		assertCertCheckStage(t, err, certCheckSelfTest)
	}
	if *orders != 0 {
		t.Fatalf("expected no ACME order, got %d", *orders)
	}
	if err := certOrders.Check(certOrderCooldownKey(certConfig)); err != nil {
		t.Fatalf("expected self-test failures not to start a cooldown, got %v", err)
	}
}

func TestRequestCertOrdersAfterSelfTestPasses(t *testing.T) {
	orders := stubCertIssuance(t, nil, acmeRejection("dns problem"))
	certConfig := validDNSCertConfig(t)

	err := (&Controller{}).requestCert(&panel.NodeInfo{CertConfig: certConfig})
	if err == nil || !strings.Contains(err.Error(), "dns problem") {
		t.Fatalf("expected the ACME error, got %v", err)
	}
	if *orders != 1 {
		t.Fatalf("expected one ACME order, got %d", *orders)
	}
	if err := certOrders.Check(certOrderCooldownKey(certConfig)); err == nil {
		t.Fatal("expected an ACME rejection to start a cooldown")
	}
}

func writeTestCertificate(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "us.example.com"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertRenewalDue(t *testing.T) {
	now := time.Now()
	directory := t.TempDir()
	tests := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"fresh", now.Add(60 * 24 * time.Hour), false},
		{"just outside window", now.Add(31*24*time.Hour + time.Hour), false},
		{"inside window", now.Add(30*24*time.Hour + time.Hour), true},
		{"expired", now.Add(-time.Hour), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(directory, tt.name+".cer")
			writeTestCertificate(t, path, tt.notAfter)
			got, err := certRenewalDue(path, now)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("expected due=%v, got %v", tt.want, got)
			}
		})
	}
}

func TestRenewCertTaskSkipsChecksUntilRenewalIsDue(t *testing.T) {
	stubCertIssuance(t, errors.New("self-test must not run"), nil)
	renewals := 0
	previousRenew := renewIssuedCert
	renewIssuedCert = func(*conf.CertConfig) error {
		renewals++
		return nil
	}
	t.Cleanup(func() { renewIssuedCert = previousRenew })

	certConfig := validDNSCertConfig(t)
	writeTestCertificate(t, certConfig.CertFile, time.Now().Add(60*24*time.Hour))
	if err := (&Controller{}).renewCertTask(certConfig); err != nil {
		t.Fatal(err)
	}
	if renewals != 0 {
		t.Fatalf("expected no renewal for a fresh certificate, got %d", renewals)
	}
}

func TestRenewCertTaskRunsSelfTestBeforeRenewing(t *testing.T) {
	stubCertIssuance(t, &certCheckError{Stage: certCheckSelfTest, Err: errors.New("zone could not be found")}, nil)
	renewals := 0
	previousRenew := renewIssuedCert
	renewIssuedCert = func(*conf.CertConfig) error {
		renewals++
		return nil
	}
	t.Cleanup(func() { renewIssuedCert = previousRenew })

	certConfig := validDNSCertConfig(t)
	writeTestCertificate(t, certConfig.CertFile, time.Now().Add(10*24*time.Hour))
	if err := (&Controller{}).renewCertTask(certConfig); err != nil {
		t.Fatal(err)
	}
	if renewals != 0 {
		t.Fatalf("expected renewal to wait for a passing self-test, got %d", renewals)
	}
}
