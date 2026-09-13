package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Designdocs/N2X/conf"
)

const (
	// A rejection from the CA spends a failed-authorization slot; Let's
	// Encrypt locks the identifier for an hour after five of them. A 5m base
	// doubling to 1h keeps at most four inside any first hour.
	acmeRejectionBackoffBase = 5 * time.Minute
	acmeRejectionBackoffMax  = time.Hour
	// Anything else (network errors, DNS propagation timeouts, write errors)
	// never reached a validation, so it only needs to avoid hammering.
	localFailureBackoffBase = time.Minute
	localFailureBackoffMax  = 10 * time.Minute
	// Used when a rate-limit response carries no parsable retry-after time.
	rateLimitDefaultPause = time.Hour
	rateLimitMaxPause     = 7 * 24 * time.Hour

	acmeProblemPrefix     = "urn:ietf:params:acme:error:"
	acmeRateLimited       = acmeProblemPrefix + "rateLimited"
	retryAfterLayout      = "2006-01-02 15:04:05 MST"
	certOrderKeySeparator = "\x00"
)

// lego flattens per-domain challenge failures into a map-typed error that
// does not unwrap, so the ACME problem type is only reliably visible in the
// message text.
var retryAfterPattern = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)`)

// certOrders throttles ACME orders for a certificate that just failed, so
// the startup retry and the per-pull reload path cannot run the domain into
// the CA's rate limits.
var certOrders = newCertOrderCooldown(time.Now)

type certOrderFailure struct {
	acmeRejections int
	localFailures  int
	retryAt        time.Time
	lastErr        error
}

type certOrderCooldown struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]certOrderFailure
}

func newCertOrderCooldown(now func() time.Time) *certOrderCooldown {
	return &certOrderCooldown{
		now:     now,
		entries: make(map[string]certOrderFailure),
	}
}

// Check returns an error while the order identified by key is paused.
func (c *certOrderCooldown) Check(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.retryAt) {
		return nil
	}
	return fmt.Errorf(
		"certificate order paused until %s after %d failed attempt(s), last error: %v",
		entry.retryAt.Format(time.RFC3339), entry.acmeRejections+entry.localFailures, entry.lastErr)
}

func (c *certOrderCooldown) RecordFailure(key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	entry := c.entries[key]
	entry.lastErr = err
	message := err.Error()
	switch {
	case strings.Contains(message, acmeRateLimited):
		entry.acmeRejections++
		entry.retryAt = now.Add(rateLimitPause(message, now))
	case strings.Contains(message, acmeProblemPrefix):
		entry.acmeRejections++
		entry.retryAt = now.Add(doublingBackoff(acmeRejectionBackoffBase, acmeRejectionBackoffMax, entry.acmeRejections))
	default:
		entry.localFailures++
		entry.retryAt = now.Add(doublingBackoff(localFailureBackoffBase, localFailureBackoffMax, entry.localFailures))
	}
	c.entries[key] = entry
}

func (c *certOrderCooldown) RecordSuccess(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func doublingBackoff(base, maxDelay time.Duration, failures int) time.Duration {
	delay := base
	for i := 1; i < failures && delay < maxDelay; i++ {
		delay *= 2
	}
	return min(delay, maxDelay)
}

func rateLimitPause(message string, now time.Time) time.Duration {
	match := retryAfterPattern.FindStringSubmatch(message)
	if match == nil {
		return rateLimitDefaultPause
	}
	retryAt, err := time.Parse(retryAfterLayout, match[1])
	if err != nil {
		return rateLimitDefaultPause
	}
	return min(max(retryAt.Sub(now), localFailureBackoffBase), rateLimitMaxPause)
}

// certOrderCooldownKey identifies an order by what it asks for and the
// credentials it asks with, so fixing a DNS token lifts the pause right away.
// The credentials are hashed: the key ends up in memory and error paths.
func certOrderCooldownKey(certConfig *conf.CertConfig) string {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(certConfig.CertDomain)), ".")

	keys := make([]string, 0, len(certConfig.DNSEnv))
	for key := range certConfig.DNSEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	hash := sha256.New()
	fmt.Fprint(hash, certConfig.Provider, certOrderKeySeparator, certConfig.Email, certOrderKeySeparator)
	for _, key := range keys {
		fmt.Fprint(hash, key, "=", certConfig.DNSEnv[key], certOrderKeySeparator)
	}
	return certConfig.CertMode + "|" + domain + "|" + hex.EncodeToString(hash.Sum(nil))
}
