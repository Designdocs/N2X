package conf

import (
	"encoding/json"

	"github.com/Designdocs/N2X/decoy"
)

type XrayConfig struct {
	LogConfig          *XrayLogConfig        `json:"Log"`
	AssetPath          string                `json:"AssetPath"`
	DnsConfigPath      string                `json:"DnsConfigPath"`
	RouteConfigPath    string                `json:"RouteConfigPath"`
	ConnectionConfig   *XrayConnectionConfig `json:"ConnectionConfig"`
	LegacyConnConfig   *XrayConnectionConfig `json:"XrayConnectionConfig"`
	InboundConfigPath  string                `json:"InboundConfigPath"`
	OutboundConfigPath string                `json:"OutboundConfigPath"`
	// EnableBTExtraSniffing toggles the DHT and UDP tracker sniffers. It is a
	// pointer so an absent key means enabled: UnmarshalJSON decodes into a
	// zero struct, which would turn a plain bool off for every config file
	// written before this option existed.
	EnableBTExtraSniffing *bool `json:"EnableBTExtraSniffing"`
}

// BTExtraSniffingEnabled reports whether the DHT and UDP tracker sniffers
// should be registered. Enabled unless explicitly set to false.
func (x *XrayConfig) BTExtraSniffingEnabled() bool {
	return x.EnableBTExtraSniffing == nil || *x.EnableBTExtraSniffing
}

type XrayLogConfig struct {
	Level      string `json:"Level"`
	AccessPath string `json:"AccessPath"`
	ErrorPath  string `json:"ErrorPath"`
}

type XrayConnectionConfig struct {
	StatsUserUplink   bool   `json:"statsUserUplink"`
	StatsUserDownlink bool   `json:"statsUserDownlink"`
	Handshake         uint32 `json:"handshake"`
	ConnIdle          uint32 `json:"connIdle"`
	UplinkOnly        uint32 `json:"uplinkOnly"`
	DownlinkOnly      uint32 `json:"downlinkOnly"`
	BufferSize        int32  `json:"bufferSize"`
}

func NewXrayConfig() *XrayConfig {
	return &XrayConfig{
		LogConfig: &XrayLogConfig{
			Level:      "warning",
			AccessPath: "",
			ErrorPath:  "",
		},
		AssetPath:          "/etc/N2X/",
		DnsConfigPath:      "",
		InboundConfigPath:  "",
		OutboundConfigPath: "",
		RouteConfigPath:    "",
		ConnectionConfig: &XrayConnectionConfig{
			StatsUserUplink:   true,
			StatsUserDownlink: true,
			Handshake:         4,
			ConnIdle:          30,
			UplinkOnly:        2,
			DownlinkOnly:      4,
			BufferSize:        64,
		},
	}
}

type _XrayConfig XrayConfig

func (x *XrayConfig) UnmarshalJSON(b []byte) error {
	// Decode on top of whatever the caller pre-populated (CoreConfig hands us
	// a NewXrayConfig) instead of a zero value, so omitting a key keeps its
	// default. Starting from zero silently dropped ConnectionConfig, and
	// parseConnectionConfig then panicked on the nil pointer.
	tmp := _XrayConfig(*x)
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*x = XrayConfig(tmp)
	if x.ConnectionConfig == nil && x.LegacyConnConfig != nil {
		x.ConnectionConfig = x.LegacyConnConfig
	}
	return nil
}

type XrayOptions struct {
	EnableProxyProtocol bool   `json:"EnableProxyProtocol"`
	EnableDNS           bool   `json:"EnableDNS"`
	DNSType             string `json:"DNSType"`
	EnableUot           bool   `json:"EnableUot"`
	EnableTFO           bool   `json:"EnableTFO"`
	DisableIVCheck      bool   `json:"DisableIVCheck"`
	DisableSniffing     bool   `json:"DisableSniffing"`
	EnableFallback      bool   `json:"EnableFallback"`
	// DecoyFallback turns on fallback and, when FallBackConfigs is empty,
	// points it at the companion web service installed with the node. It exists
	// so serving a page on port 443 does not require running a separate web
	// server or hand-writing a destination.
	DecoyFallback   bool                    `json:"DecoyFallback"`
	FallBackConfigs []FallBackConfigForXray `json:"FallBackConfigs"`
}

// FallbackEnabled reports whether inbound fallback should be configured at all.
func (x *XrayOptions) FallbackEnabled() bool {
	if x == nil {
		return false
	}
	return x.EnableFallback || x.DecoyFallback
}

// ResolvedFallbackConfigs returns the fallback entries to build, substituting a
// single companion web service entry when DecoyFallback is on and the operator
// has not written their own. Explicit entries always win.
//
// The returned slice is freshly allocated so callers cannot write through to
// the stored configuration across reloads.
func (x *XrayOptions) ResolvedFallbackConfigs() []FallBackConfigForXray {
	if x == nil {
		return nil
	}
	if len(x.FallBackConfigs) > 0 {
		return x.FallBackConfigs
	}
	if !x.DecoyFallback {
		return nil
	}
	return []FallBackConfigForXray{{Dest: decoy.Selector}}
}

type FallBackConfigForXray struct {
	SNI              string `json:"SNI"`
	Alpn             string `json:"Alpn"`
	Path             string `json:"Path"`
	Dest             string `json:"Dest"`
	ProxyProtocolVer uint64 `json:"ProxyProtocolVer"`
}

func NewXrayOptions() *XrayOptions {
	return &XrayOptions{
		EnableProxyProtocol: false,
		EnableDNS:           false,
		DNSType:             "AsIs",
		EnableUot:           false,
		EnableTFO:           false,
		DisableIVCheck:      false,
		DisableSniffing:     false,
		EnableFallback:      false,
	}
}
