package conf

import "encoding/json"

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

	return nil
}

func NewCertConfig() *CertConfig {
	return &CertConfig{
		CertMode: "none",
	}
}
