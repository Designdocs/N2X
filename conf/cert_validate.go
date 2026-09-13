package conf

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"path/filepath"
	"strings"
)

const (
	maxCertDomainLength = 253
	maxCertDomainLabel  = 63
)

// ValidateACMECertConfig checks a dns or http mode cert config without
// touching the network or the filesystem. It is run both when the config
// file is loaded and right before every ACME order.
func ValidateACMECertConfig(c *CertConfig) error {
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("CertFile and KeyFile are required")
	}
	if filepath.Clean(c.CertFile) == filepath.Clean(c.KeyFile) {
		return fmt.Errorf("CertFile and KeyFile point to the same file %s", c.CertFile)
	}
	if err := validateCertDomain(c.CertDomain, c.CertMode == "dns"); err != nil {
		return err
	}
	if c.Email != "" {
		address, err := mail.ParseAddress(c.Email)
		if err != nil || address.Name != "" || address.Address != c.Email {
			return fmt.Errorf("email %q is not a plain email address", c.Email)
		}
	}
	if c.CertMode != "dns" {
		return nil
	}
	switch strings.TrimSpace(c.Provider) {
	case "":
		return errors.New("DNS provider is required in dns mode")
	case "manual":
		return fmt.Errorf("DNS provider %q waits for console input and cannot run as a service", c.Provider)
	}
	for key, value := range c.DNSEnv {
		if strings.TrimSpace(key) == "" {
			return errors.New("DNSEnv contains an empty variable name")
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("DNSEnv %s is empty", key)
		}
	}
	return nil
}

func validateCertDomain(domain string, allowWildcard bool) error {
	if strings.TrimSpace(domain) == "" {
		return errors.New("certificate domain (CertDomain) is required")
	}
	name := strings.TrimSuffix(strings.ToLower(domain), ".")
	if net.ParseIP(name) != nil {
		return fmt.Errorf("CertDomain %q is an IP address; ACME certificates here need a domain name", domain)
	}
	if strings.HasPrefix(name, "*.") {
		if !allowWildcard {
			return fmt.Errorf("wildcard CertDomain %q requires dns mode", domain)
		}
		name = strings.TrimPrefix(name, "*.")
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("CertDomain %q: a wildcard is only allowed as the whole leftmost label", domain)
	}
	if len(name) > maxCertDomainLength {
		return fmt.Errorf("CertDomain %q is longer than %d characters", domain, maxCertDomainLength)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("CertDomain %q is not a public domain name", domain)
	}
	for _, label := range labels {
		if !validDomainLabel(label) {
			return fmt.Errorf("CertDomain %q is not a valid domain name (only letters, digits, '-' and '.'; no scheme, port or path)", domain)
		}
	}
	return nil
}

func validDomainLabel(label string) bool {
	if label == "" || len(label) > maxCertDomainLabel || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
