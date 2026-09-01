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
	HysteriaOptions          *HysteriaOptions       `json:"HysteriaOptions"`
	TuicOptions              *TuicOptions           `json:"TuicOptions"`
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

// HysteriaOptions holds the node-local Hysteria settings a panel cannot
// express.
type HysteriaOptions struct {
	// PortHopping lists the UDP port ranges redirected to the node's listen
	// port, e.g. ["20000-30000"]. It is the fallback for panels that do not
	// send server_ports themselves; the panel's value wins when both are set.
	//
	// The redirect is a nat PREROUTING rule, so this only works on Linux and
	// only when N2X can run iptables.
	PortHopping []string `json:"PortHopping"`

	// Masquerade is what a Hysteria2 node answers ordinary HTTP requests
	// with, so an active prober sees a website instead of a proxy. Either a
	// site to reverse proxy ("https://news.example.com") or a directory to
	// serve ("file:///var/www/html"). The panel's value wins when both are
	// set.
	Masquerade string `json:"Masquerade"`

	// BrutalDebug logs the Brutal congestion controller's decisions. Debug
	// only: it is noisy under load.
	BrutalDebug bool `json:"BrutalDebug"`

	// QUIC flow control and connection limits for Hysteria v1 nodes. Zero
	// keeps the sing-box default, and the panel's value wins when both are
	// set. These do not apply to Hysteria2, which manages its own windows.
	ReceiveWindowConn   uint64 `json:"ReceiveWindowConn"`
	ReceiveWindowClient uint64 `json:"ReceiveWindowClient"`
	MaxConnClient       int    `json:"MaxConnClient"`
	DisableMTUDiscovery bool   `json:"DisableMTUDiscovery"`
}

// TuicOptions holds the node-local TUIC settings a panel cannot express. Every
// field falls back to what the panel sent when left empty.
type TuicOptions struct {
	// AuthTimeout is how long a new connection has to authenticate before it
	// is dropped, as a duration string ("3s").
	AuthTimeout string `json:"AuthTimeout"`
	// Heartbeat is the keep-alive interval for an idle connection ("10s").
	// Raising it saves battery on mobile clients; lowering it detects a dead
	// peer sooner.
	Heartbeat string `json:"Heartbeat"`
	// CongestionControl is "cubic", "new_reno" or "bbr".
	CongestionControl string `json:"CongestionControl"`
}

// ShadowTLSHandshakeTarget is one camouflage handshake upstream. A zero port
// means 443.
type ShadowTLSHandshakeTarget struct {
	Server     string `json:"Server"`
	ServerPort uint16 `json:"ServerPort"`
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
	// HandshakeForServerName relays the camouflage handshake to a different
	// upstream depending on the SNI the client asked for. Entries here
	// override the panel's for the same server name; anything not listed
	// falls back to the primary handshake target.
	HandshakeForServerName map[string]ShadowTLSHandshakeTarget `json:"HandshakeForServerName"`
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
