package node

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// acmeRejection mimics how lego surfaces a failed validation: the problem
// document is flattened into the resolver's per-domain error map, so only its
// text survives, not the *acme.ProblemDetails value.
func acmeRejection(detail string) error {
	return errors.New("error: one or more domains had a problem:\n[us.example.com] invalid authorization: " +
		"acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: " + detail)
}

func assertPausedFor(t *testing.T, clock *fakeClock, cooldown *certOrderCooldown, key string, wait time.Duration, lastErr string) {
	t.Helper()
	clock.Advance(wait - time.Second)
	err := cooldown.Check(key)
	if err == nil {
		t.Fatalf("expected order to be paused just before %s", wait)
	}
	if !strings.Contains(err.Error(), lastErr) {
		t.Fatalf("expected last error %q in message, got %v", lastErr, err)
	}
	clock.Advance(time.Second)
	if err := cooldown.Check(key); err != nil {
		t.Fatalf("expected order to be allowed after %s, got %v", wait, err)
	}
}

func TestCertOrderCooldownBacksOffAfterACMERejections(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	cooldown := newCertOrderCooldown(clock.Now)
	const key = "dns|us.example.com"

	if err := cooldown.Check(key); err != nil {
		t.Fatalf("expected first order to be allowed, got %v", err)
	}

	expected := []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		time.Hour,
		time.Hour,
	}
	for _, wait := range expected {
		cooldown.RecordFailure(key, acmeRejection("zone could not be found"))
		assertPausedFor(t, clock, cooldown, key, wait, "zone could not be found")
	}
}

func TestCertOrderCooldownRetriesLocalFailuresSooner(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	cooldown := newCertOrderCooldown(clock.Now)
	const key = "dns|us.example.com"

	// Failures that never reached a Let's Encrypt validation (network errors,
	// DNS propagation timeouts, write errors) cost no authorization quota.
	expected := []time.Duration{
		time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		10 * time.Minute,
		10 * time.Minute,
	}
	for _, wait := range expected {
		cooldown.RecordFailure(key, errors.New("dial tcp: i/o timeout"))
		assertPausedFor(t, clock, cooldown, key, wait, "i/o timeout")
	}
}

func TestCertOrderCooldownLocalFailuresDoNotEscalateACMEBackoff(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	cooldown := newCertOrderCooldown(clock.Now)
	const key = "dns|us.example.com"

	cooldown.RecordFailure(key, acmeRejection("first"))
	assertPausedFor(t, clock, cooldown, key, 5*time.Minute, "first")
	cooldown.RecordFailure(key, errors.New("connection reset"))
	assertPausedFor(t, clock, cooldown, key, time.Minute, "connection reset")
	cooldown.RecordFailure(key, acmeRejection("second"))
	assertPausedFor(t, clock, cooldown, key, 10*time.Minute, "second")
}

func TestCertOrderCooldownHonoursRateLimitRetryAfter(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	cooldown := newCertOrderCooldown(clock.Now)
	const key = "dns|us.example.com"

	cooldown.RecordFailure(key, errors.New(
		"acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: "+
			"urn:ietf:params:acme:error:rateLimited :: too many failed authorizations (5) for "+
			"\"us.example.com\" in the last 1h0m0s, retry after 2026-09-13 00:37:12 UTC: see "+
			"https://letsencrypt.org/docs/rate-limits/"))
	assertPausedFor(t, clock, cooldown, key, 37*time.Minute+12*time.Second, "rateLimited")

	cooldown.RecordFailure(key, errors.New(
		"acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: slow down"))
	assertPausedFor(t, clock, cooldown, key, time.Hour, "slow down")
}

func TestCertOrderCooldownResetsOnSuccess(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	cooldown := newCertOrderCooldown(clock.Now)
	const key = "dns|us.example.com"

	cooldown.RecordFailure(key, acmeRejection("first"))
	cooldown.RecordFailure(key, acmeRejection("second"))
	cooldown.RecordSuccess(key)
	if err := cooldown.Check(key); err != nil {
		t.Fatalf("expected success to clear cooldown, got %v", err)
	}

	cooldown.RecordFailure(key, acmeRejection("third"))
	clock.Advance(5 * time.Minute)
	if err := cooldown.Check(key); err != nil {
		t.Fatalf("expected backoff to restart from the base delay, got %v", err)
	}
}

func TestCertOrderCooldownKeyTracksCredentials(t *testing.T) {
	base := &conf.CertConfig{
		CertMode:   "dns",
		CertDomain: "us.example.com",
		Provider:   "cloudflare",
		Email:      "ops@example.com",
		DNSEnv:     map[string]string{"CF_DNS_API_TOKEN": "old", "CF_ZONE_API_TOKEN": "zone"},
	}
	same := &conf.CertConfig{
		CertMode:   "dns",
		CertDomain: "US.example.com.",
		Provider:   "cloudflare",
		Email:      "ops@example.com",
		DNSEnv:     map[string]string{"CF_ZONE_API_TOKEN": "zone", "CF_DNS_API_TOKEN": "old"},
	}
	rotated := &conf.CertConfig{
		CertMode:   "dns",
		CertDomain: "us.example.com",
		Provider:   "cloudflare",
		Email:      "ops@example.com",
		DNSEnv:     map[string]string{"CF_DNS_API_TOKEN": "new", "CF_ZONE_API_TOKEN": "zone"},
	}

	if certOrderCooldownKey(base) != certOrderCooldownKey(same) {
		t.Fatal("expected equivalent configs to share a cooldown")
	}
	if certOrderCooldownKey(base) == certOrderCooldownKey(rotated) {
		t.Fatal("expected a rotated DNS token to bypass the old cooldown")
	}
	if strings.Contains(certOrderCooldownKey(base), "old") {
		t.Fatal("cooldown key must not carry DNS credentials in clear text")
	}
}

func TestRequestCertSkipsACMEWhileCoolingDown(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	previous := certOrders
	certOrders = newCertOrderCooldown(clock.Now)
	t.Cleanup(func() { certOrders = previous })

	directory := t.TempDir()
	certConfig := &conf.CertConfig{
		CertMode:   "dns",
		CertDomain: "us.example.com",
		CertFile:   filepath.Join(directory, "fullchain.cer"),
		KeyFile:    filepath.Join(directory, "cert.key"),
		Provider:   "cloudflare",
		Email:      "ops@example.com",
	}
	certOrders.RecordFailure(certOrderCooldownKey(certConfig), acmeRejection("zone could not be found"))

	controller := &Controller{}
	err := controller.requestCert(&panel.NodeInfo{CertConfig: certConfig})
	if err == nil {
		t.Fatal("expected cooldown error")
	}
	if !strings.Contains(err.Error(), "paused") {
		t.Fatalf("expected cooldown error without contacting ACME, got %v", err)
	}
}

func TestRequestCertFileModeReportsMissingFiles(t *testing.T) {
	directory := t.TempDir()
	certFile := filepath.Join(directory, "fullchain-us.example.com.cer")
	controller := &Controller{}

	err := controller.requestCert(&panel.NodeInfo{CertConfig: &conf.CertConfig{
		CertMode: "file",
		CertFile: certFile,
		KeyFile:  filepath.Join(directory, "cert-us.example.com.key"),
	}})
	if err == nil {
		t.Fatal("expected missing cert file error")
	}
	if !strings.Contains(err.Error(), certFile) {
		t.Fatalf("expected error to name %s, got %v", certFile, err)
	}
}
