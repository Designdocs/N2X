package node

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Designdocs/N2X/conf"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	log "github.com/sirupsen/logrus"
)

// Every failed ACME order spends Let's Encrypt quota, and a handful of them
// locks the domain for an hour. Mistakes that can be caught locally therefore
// have to be caught before an order is placed: first a static check of the
// config, then a self-test that exercises the same DNS credentials, port and
// directories the order is about to use.

type certCheckStage string

const (
	certCheckConfig   certCheckStage = "config"
	certCheckSelfTest certCheckStage = "self-test"

	certSelfTestTimeout = 10 * time.Second
	// Some providers poll their own API until a change is live, so this is
	// generous; it only has to stop a hung API from wedging the caller.
	dnsSelfTestTimeout      = 2 * time.Minute
	httpChallengeAddr       = ":80"
	minRedactedSecretLength = 8
)

// certCheckError marks a certificate problem found before contacting the
// CA. It never counts toward the order cooldown: no quota was spent, and
// the order should go out as soon as the problem is fixed.
type certCheckError struct {
	Stage certCheckStage
	Err   error
}

func (e *certCheckError) Error() string {
	return fmt.Sprintf("certificate %s check failed, no ACME order placed: %v", e.Stage, e.Err)
}

func (e *certCheckError) Unwrap() error { return e.Err }

func configError(format string, args ...any) error {
	return &certCheckError{Stage: certCheckConfig, Err: fmt.Errorf(format, args...)}
}

func selfTestError(format string, args ...any) error {
	return &certCheckError{Stage: certCheckSelfTest, Err: fmt.Errorf(format, args...)}
}

// validateCertConfig checks an ACME (dns/http) cert config without touching
// the network or the filesystem.
func validateCertConfig(certConfig *conf.CertConfig) error {
	if err := conf.ValidateACMECertConfig(certConfig); err != nil {
		return &certCheckError{Stage: certCheckConfig, Err: err}
	}
	return nil
}

type certPreflight struct {
	newDNSProvider func(name string, envs map[string]string) (challenge.Provider, error)
	listen         func(network, address string) (net.Listener, error)
	lookupIP       func(ctx context.Context, host string) ([]net.IPAddr, error)
	dnsTimeout     time.Duration
}

func newCertPreflight() *certPreflight {
	return &certPreflight{
		dnsTimeout: dnsSelfTestTimeout,
		newDNSProvider: func(name string, envs map[string]string) (challenge.Provider, error) {
			return newScopedDNSProvider(name, envs, dns.NewDNSChallengeProviderByName)
		},
		listen:   net.Listen,
		lookupIP: net.DefaultResolver.LookupIPAddr,
	}
}

var runCertPreflight = newCertPreflight().Run

// Run self-tests everything an ACME order for certConfig depends on that can
// be verified without the CA.
func (p *certPreflight) Run(certConfig *conf.CertConfig) error {
	// Checked first: an order that succeeds but cannot be saved still burns
	// the weekly duplicate-certificate limit.
	for _, directory := range certDirectories(certConfig) {
		if err := checkDirectoryWritable(directory); err != nil {
			return selfTestError("certificate directory %s is not writable: %w", directory, err)
		}
	}
	switch certConfig.CertMode {
	case "dns":
		return p.checkDNS(certConfig)
	case "http":
		return p.checkHTTP(certConfig)
	}
	return nil
}

func certDirectories(certConfig *conf.CertConfig) []string {
	certDir := filepath.Dir(certConfig.CertFile)
	directories := []string{certDir, filepath.Join(certDir, "user")}
	if keyDir := filepath.Dir(certConfig.KeyFile); keyDir != certDir {
		directories = append(directories, keyDir)
	}
	return directories
}

func checkDirectoryWritable(directory string) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(directory, ".n2x-write-check-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

// checkDNS creates and removes a throwaway _acme-challenge TXT record with
// the node's own credentials. That is exactly what the DNS-01 challenge
// does, so a missing zone permission or a zone in another account fails
// here instead of at the CA.
func (p *certPreflight) checkDNS(certConfig *conf.CertConfig) error {
	provider, err := p.newDNSProvider(certConfig.Provider, certConfig.DNSEnv)
	if err != nil {
		return configError("DNS provider %q rejected DNSEnv: %w",
			certConfig.Provider, redactDNSEnv(err, certConfig.DNSEnv))
	}
	domain := strings.TrimPrefix(strings.TrimSuffix(certConfig.CertDomain, "."), "*.")
	token, err := randomChallengeToken()
	if err != nil {
		return selfTestError("generate test token: %w", err)
	}

	// challenge.Provider takes no context, so a hung provider API is bounded
	// by abandoning the goroutine. It still cleans up if Present returns late.
	result := make(chan error, 1)
	go func() { result <- presentAndCleanUp(provider, domain, token, certConfig.Provider) }()
	timer := time.NewTimer(p.dnsTimeout)
	defer timer.Stop()
	select {
	case err = <-result:
	case <-timer.C:
		return selfTestError("DNS provider %s timed out after %s while creating a test record for %s",
			certConfig.Provider, p.dnsTimeout, domain)
	}
	if err != nil {
		return &certCheckError{Stage: certCheckSelfTest, Err: redactDNSEnv(err, certConfig.DNSEnv)}
	}
	log.WithField("domain", certConfig.CertDomain).Info("Certificate DNS self-test passed")
	return nil
}

func presentAndCleanUp(provider challenge.Provider, domain, token, providerName string) error {
	keyAuth := token + ".n2x-self-test"
	if err := provider.Present(domain, token, keyAuth); err != nil {
		return fmt.Errorf("create test TXT record _acme-challenge.%s via %s (check the credentials can edit this zone): %w",
			domain, providerName, err)
	}
	if err := provider.CleanUp(domain, token, keyAuth); err != nil {
		return fmt.Errorf("remove test TXT record _acme-challenge.%s via %s: %w", domain, providerName, err)
	}
	return nil
}

// redactDNSEnv masks DNS credentials that a provider echoed into an error,
// since these errors end up in the service log. Short values (TTLs, flags)
// are left alone: they are not secrets and would mangle unrelated text.
func redactDNSEnv(err error, envs map[string]string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	redacted := message
	for _, value := range envs {
		if len(value) >= minRedactedSecretLength {
			redacted = strings.ReplaceAll(redacted, value, "[REDACTED]")
		}
	}
	if redacted == message {
		return err
	}
	return errors.New(redacted)
}

func (p *certPreflight) checkHTTP(certConfig *conf.CertConfig) error {
	listener, err := p.listen("tcp", httpChallengeAddr)
	if err != nil {
		return selfTestError("port 80 is needed for the HTTP-01 challenge but cannot be bound: %w", err)
	}
	if err := listener.Close(); err != nil {
		return selfTestError("release port 80 after probing: %w", err)
	}

	domain := strings.TrimSuffix(certConfig.CertDomain, ".")
	ctx, cancel := context.WithTimeout(context.Background(), certSelfTestTimeout)
	defer cancel()
	addresses, err := p.lookupIP(ctx, domain)
	if err != nil {
		return selfTestError("domain %s does not resolve: %w", domain, err)
	}
	if len(addresses) == 0 {
		return selfTestError("domain %s has no A or AAAA record", domain)
	}
	log.WithField("domain", certConfig.CertDomain).Info("Certificate HTTP self-test passed")
	return nil
}

func randomChallengeToken() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
