package conf

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DDNSConfig is opt-in and independent of certificate issuance. Empty provider,
// domain and credentials may reuse the local certificate settings.
type DDNSConfig struct {
	Enabled    bool              `json:"Enabled"`
	Provider   string            `json:"Provider"`
	Domain     string            `json:"Domain"`
	ZoneName   string            `json:"ZoneName"`
	RecordType string            `json:"RecordType"`
	Interval   int               `json:"Interval"` // seconds
	TTL        int               `json:"TTL"`
	IPURL      string            `json:"IPURL"`
	DNSEnv     map[string]string `json:"DNSEnv"`
}

func (c DDNSConfig) Effective(cert *CertConfig) DDNSConfig {
	if cert != nil {
		if c.Provider == "" {
			c.Provider = cert.Provider
		}
		if c.Domain == "" {
			c.Domain = cert.CertDomain
		}
		if len(c.DNSEnv) == 0 && strings.EqualFold(strings.TrimSpace(c.Provider), strings.TrimSpace(cert.Provider)) {
			c.DNSEnv = cert.DNSEnv
		}
	}
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	c.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Domain), "."))
	c.ZoneName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.ZoneName), "."))
	if c.ZoneName == "" {
		c.ZoneName, _ = publicsuffix.EffectiveTLDPlusOne(c.Domain)
	}
	c.RecordType = strings.ToUpper(strings.TrimSpace(c.RecordType))
	if c.RecordType == "" {
		c.RecordType = "A"
	}
	if c.Interval == 0 {
		c.Interval = 300
	}
	if c.TTL == 0 {
		c.TTL = 600
	}
	if c.IPURL == "" {
		c.IPURL = "https://api.ipify.org"
		if c.RecordType == "AAAA" {
			c.IPURL = "https://api6.ipify.org"
		}
	}
	return c
}

func (c DDNSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Provider != "cloudflare" && c.Provider != "alidns" {
		return fmt.Errorf("Provider must be cloudflare or alidns (Alibaba Cloud international)")
	}
	if err := validateCertDomain(c.Domain, false); err != nil {
		return fmt.Errorf("Domain must be a concrete DNS hostname: %w", err)
	}
	if err := validateCertDomain(c.ZoneName, false); err != nil {
		return fmt.Errorf("ZoneName must be the DNS zone hosting Domain: %w", err)
	}
	if c.Domain != c.ZoneName && !strings.HasSuffix(c.Domain, "."+c.ZoneName) {
		return fmt.Errorf("Domain must be inside ZoneName")
	}
	if c.RecordType != "A" && c.RecordType != "AAAA" {
		return fmt.Errorf("RecordType must be A or AAAA")
	}
	if c.Interval < 30 || c.Interval > 86400 {
		return fmt.Errorf("Interval must be between 30 and 86400 seconds")
	}
	if c.TTL != 1 && (c.TTL < 60 || c.TTL > 86400) || c.Provider == "alidns" && c.TTL < 600 {
		return fmt.Errorf("TTL must be 60..86400 (Cloudflare also accepts 1 for automatic TTL; alidns requires at least 600)")
	}
	u, err := url.Parse(c.IPURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("IPURL must be an HTTPS URL returning a plain public IP address")
	}
	keys := []string{"CF_DNS_API_TOKEN"}
	if c.Provider == "alidns" {
		keys = []string{"ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"}
	}
	for _, key := range keys {
		if strings.TrimSpace(c.DNSEnv[key]) == "" {
			return fmt.Errorf("DNSEnv.%s is required (or provide it in the matching CertConfig)", key)
		}
	}
	return nil
}
