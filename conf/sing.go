package conf

// This file intentionally avoids importing github.com/sagernet/sing-box so
// that xray-only builds do not link the sing-box option tree. Values that map
// onto sing-box enums (DomainStrategy, ShadowTLS wildcard SNI, ...) are kept
// as plain strings here and translated inside core/sing.

type SingConfig struct {
	LogConfig    SingLogConfig `json:"Log"`
	NtpConfig    SingNtpConfig `json:"NTP"`
	OriginalPath string        `json:"OriginalPath"`
}

type SingLogConfig struct {
	Disabled  bool   `json:"Disable"`
	Level     string `json:"Level"`
	Output    string `json:"Output"`
	Timestamp bool   `json:"Timestamp"`
}

type SingNtpConfig struct {
	Enable     bool   `json:"Enable"`
	Server     string `json:"Server"`
	ServerPort uint16 `json:"ServerPort"`
}

func NewSingConfig() *SingConfig {
	return &SingConfig{
		LogConfig: SingLogConfig{
			Level:     "error",
			Timestamp: true,
		},
		NtpConfig: SingNtpConfig{
			Enable:     false,
			Server:     "time.apple.com",
			ServerPort: 0,
		},
	}
}

type SingOptions struct {
	TCPFastOpen              bool                   `json:"EnableTFO"`
	SniffEnabled             bool                   `json:"EnableSniff"`
	SniffOverrideDestination bool                   `json:"SniffOverrideDestination"`
	EnableDNS                bool                   `json:"EnableDNS"`
	DomainStrategy           string                 `json:"DomainStrategy"`
	FallBackConfigs          *FallBackConfigForSing `json:"FallBackConfigs"`
	Multiplex                *MultiplexConfig       `json:"MultiplexConfig"`
	ShadowTLSOptions         *ShadowTLSOptions      `json:"ShadowTLSOptions"`
	NaiveOptions             *NaiveOptions          `json:"NaiveOptions"`
}

type FallBackConfigForSing struct {
	FallBack        FallBack            `json:"FallBack"`
	FallBackForALPN map[string]FallBack `json:"FallBackForALPN"`
}

type FallBack struct {
	Server     string `json:"Server"`
	ServerPort string `json:"ServerPort"`
}

type MultiplexConfig struct {
	Enabled bool          `json:"Enable"`
	Padding bool          `json:"Padding"`
	Brutal  BrutalOptions `json:"Brutal"`
}

type BrutalOptions struct {
	Enabled  bool `json:"Enable"`
	UpMbps   int  `json:"UpMbps"`
	DownMbps int  `json:"DownMbps"`
}

// ShadowTLSOptions holds the local overrides for a ShadowTLS node. Every field
// falls back to the value the panel supplied when left empty, so a deployment
// only needs to set what the panel cannot express.
type ShadowTLSOptions struct {
	// Version pins the ShadowTLS protocol version (1, 2 or 3). Zero keeps the
	// panel's value.
	Version int `json:"Version"`
	// HandshakeServer overrides the camouflage target hostname.
	HandshakeServer string `json:"HandshakeServer"`
	// HandshakeServerPort overrides the camouflage target port.
	HandshakeServerPort uint16 `json:"HandshakeServerPort"`
	// StrictMode enables v3 strict mode, which rejects clients whose TLS
	// records do not match the handshake target. Recommended when the
	// camouflage target is under your control.
	StrictMode bool `json:"StrictMode"`
	// WildcardSNI is "off", "authed" or "all".
	WildcardSNI string `json:"WildcardSNI"`
}

// NaiveOptions holds the local overrides for a NaiveProxy node.
type NaiveOptions struct {
	// Network restricts the listener to "tcp" (HTTP/2) or "udp" (HTTP/3).
	// Empty keeps the panel's value, which itself defaults to both.
	Network string `json:"Network"`
}

func NewSingOptions() *SingOptions {
	return &SingOptions{
		EnableDNS:                false,
		TCPFastOpen:              false,
		SniffEnabled:             true,
		SniffOverrideDestination: true,
		FallBackConfigs:          &FallBackConfigForSing{},
		Multiplex:                &MultiplexConfig{},
	}
}
