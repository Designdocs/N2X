package conf

import (
	"encoding/json"
	"strings"
	"unicode"
)

const (
	legacyCertFile = "/etc/N2X/fullchain.cer"
	legacyKeyFile  = "/etc/N2X/cert.key"
	certFilePrefix = "/etc/N2X/fullchain-"
	certFileSuffix = ".cer"
	keyFilePrefix  = "/etc/N2X/cert-"
	keyFileSuffix  = ".key"
)

type CertConfig struct {
	CertMode         string            `json:"CertMode"` // none, file, http, dns
	RejectUnknownSni bool              `json:"RejectUnknownSni"`
	CertDomain       string            `json:"CertDomain"`
	CertFile         string            `json:"CertFile"`
	KeyFile          string            `json:"KeyFile"`
	Provider         string            `json:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email            string            `json:"Email"`
	DNSEnv           map[string]string `json:"DNSEnv"`
}

func (c *CertConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		CertMode         string            `json:"CertMode"`
		RejectUnknownSni bool              `json:"RejectUnknownSni"`
		CertDomain       string            `json:"CertDomain"`
		CertFile         string            `json:"CertFile"`
		KeyFile          string            `json:"KeyFile"`
		Provider         string            `json:"Provider"`
		Email            string            `json:"Email"`
		DNSEnv           map[string]string `json:"DNSEnv"`

		CertModeSnake         *string           `json:"cert_mode"`
		Mode                  *string           `json:"mode"`
		RejectUnknownSniSnake *bool             `json:"reject_unknown_sni"`
		CertDomainSnake       *string           `json:"cert_domain"`
		CertFileSnake         *string           `json:"cert_file"`
		KeyFileSnake          *string           `json:"key_file"`
		ProviderLower         *string           `json:"provider"`
		EmailLower            *string           `json:"email"`
		DNSEnvSnake           map[string]string `json:"dns_env"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*c = CertConfig{
		CertMode:         raw.CertMode,
		RejectUnknownSni: raw.RejectUnknownSni,
		CertDomain:       raw.CertDomain,
		CertFile:         raw.CertFile,
		KeyFile:          raw.KeyFile,
		Provider:         raw.Provider,
		Email:            raw.Email,
		DNSEnv:           raw.DNSEnv,
	}

	if raw.CertModeSnake != nil {
		c.CertMode = *raw.CertModeSnake
	} else if raw.Mode != nil {
		c.CertMode = *raw.Mode
	}
	if raw.RejectUnknownSniSnake != nil {
		c.RejectUnknownSni = *raw.RejectUnknownSniSnake
	}
	if raw.CertDomainSnake != nil {
		c.CertDomain = *raw.CertDomainSnake
	}
	if raw.CertFileSnake != nil {
		c.CertFile = *raw.CertFileSnake
	}
	if raw.KeyFileSnake != nil {
		c.KeyFile = *raw.KeyFileSnake
	}
	if raw.ProviderLower != nil {
		c.Provider = *raw.ProviderLower
	}
	if raw.EmailLower != nil {
		c.Email = *raw.EmailLower
	}
	if raw.DNSEnvSnake != nil {
		c.DNSEnv = raw.DNSEnvSnake
	}

	c.normalizeCertificatePaths()

	return nil
}

func (c *CertConfig) normalizeCertificatePaths() {
	domain := certificateFileDomain(c.CertDomain)
	if domain == "" {
		return
	}

	c.CertFile = expandCertificatePath(c.CertFile, domain)
	c.KeyFile = expandCertificatePath(c.KeyFile, domain)
	if !usesAutomaticCertificateMode(c.CertMode) || !usesManagedCertificatePaths(c.CertFile, c.KeyFile) {
		return
	}

	c.CertFile = certFilePrefix + domain + certFileSuffix
	c.KeyFile = keyFilePrefix + domain + keyFileSuffix
}

func certificateFileDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if strings.HasPrefix(domain, "*.") {
		domain = "wildcard." + strings.TrimPrefix(domain, "*.")
	}

	domain = strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '.' || character == '-' {
			return character
		}
		return '-'
	}, domain)
	return strings.Trim(domain, ".-")
}

func expandCertificatePath(path, domain string) string {
	return strings.ReplaceAll(path, "{domain}", domain)
}

func usesAutomaticCertificateMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "dns", "http", "self":
		return true
	default:
		return false
	}
}

func usesManagedCertificatePaths(certFile, keyFile string) bool {
	if isLegacyCertificatePath(certFile, legacyCertFile) && isLegacyCertificatePath(keyFile, legacyKeyFile) {
		return true
	}

	certDomain, certManaged := managedPathDomain(certFile, certFilePrefix, certFileSuffix)
	keyDomain, keyManaged := managedPathDomain(keyFile, keyFilePrefix, keyFileSuffix)
	return certManaged && keyManaged && certDomain == keyDomain
}

func isLegacyCertificatePath(path, legacyPath string) bool {
	return path == "" || path == legacyPath
}

func managedPathDomain(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}

	domain := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return domain, domain != ""
}

func NewCertConfig() *CertConfig {
	return &CertConfig{
		CertMode: "none",
	}
}
