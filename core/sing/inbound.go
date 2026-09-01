package sing

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

type HttpNetworkConfig struct {
	Header struct {
		Type     string           `json:"type"`
		Request  *json.RawMessage `json:"request"`
		Response *json.RawMessage `json:"response"`
	} `json:"header"`
}

type HttpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Headers struct {
		Host []string `json:"Host"`
	} `json:"headers"`
}

type WsNetworkConfig struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type GrpcNetworkConfig struct {
	ServiceName string `json:"serviceName"`
}

type HttpupgradeNetworkConfig struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

// buildListenOptions assembles the shared listen/sniff settings every inbound
// starts from.
func buildListenOptions(info *panel.NodeInfo, c *conf.Options) (option.ListenOptions, error) {
	addr, err := netip.ParseAddr(c.ListenIP)
	if err != nil {
		return option.ListenOptions{}, fmt.Errorf("the listen ip %q is not valid: %w", c.ListenIP, err)
	}
	listen := option.ListenOptions{
		Listen:      (*badoption.Addr)(&addr),
		ListenPort:  uint16(info.Common.ServerPort),
		TCPFastOpen: c.SingOptions.TCPFastOpen,
		InboundOptions: option.InboundOptions{
			SniffEnabled:             c.SingOptions.SniffEnabled,
			SniffOverrideDestination: c.SingOptions.SniffOverrideDestination,
			DomainStrategy:           parseDomainStrategy(c.SingOptions.DomainStrategy),
		},
	}
	return listen, nil
}

// buildTLSOptions turns the panel's security settings plus the local
// certificate config into sing-box TLS options.
func buildTLSOptions(info *panel.NodeInfo, c *conf.Options) (option.InboundTLSOptions, error) {
	var tls option.InboundTLSOptions
	switch info.Security {
	case panel.Tls:
		if c.CertConfig == nil {
			return tls, fmt.Errorf("the CertConfig is not valid")
		}
		switch c.CertConfig.CertMode {
		case "none", "":
			// TLS intentionally disabled for this node.
		default:
			tls.Enabled = true
			tls.CertificatePath = c.CertConfig.CertFile
			tls.KeyPath = c.CertConfig.KeyFile
		}
	case panel.Reality:
		// REALITY sits on the stream, below the proxy protocol, so trojan and
		// anytls nodes configure it exactly as vmess/vless ones do.
		tlsSettings, realityConfig, ok := info.RealityParams()
		if !ok {
			return tls, fmt.Errorf("the %s node type carries no reality settings", info.Type)
		}
		tls.Enabled = true
		tls.ServerName = tlsSettings.ServerName
		port, _ := strconv.Atoi(tlsSettings.ServerPort)
		dest := tlsSettings.Dest
		if dest == "" {
			dest = tls.ServerName
		}
		mtd, _ := time.ParseDuration(realityConfig.MaxTimeDiff)
		tls.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			ShortID:    []string{tlsSettings.ShortId},
			PrivateKey: tlsSettings.PrivateKey,
			Xver:       uint8(tlsSettings.Xver),
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     dest,
					ServerPort: uint16(port),
				},
			},
			MaxTimeDifference: badoption.Duration(mtd),
		}
	}
	return tls, nil
}

// buildV2RayTransport maps the panel's network settings onto a sing-box
// V2Ray transport. An empty Type means plain TCP.
func buildV2RayTransport(network string, networkSettings json.RawMessage) (option.V2RayTransportOptions, error) {
	t := option.V2RayTransportOptions{Type: network}
	switch network {
	case "", "tcp":
		// An empty network is what a panel sends for a plain TCP node.
		t.Type = ""
		if len(networkSettings) == 0 {
			return t, nil
		}
		cfg := HttpNetworkConfig{}
		if err := json.Unmarshal(networkSettings, &cfg); err != nil {
			return t, fmt.Errorf("decode NetworkSettings error: %w", err)
		}
		if cfg.Header.Type != "http" {
			return t, nil
		}
		t.Type = cfg.Header.Type
		if cfg.Header.Request == nil {
			return t, nil
		}
		var request HttpRequest
		if err := json.Unmarshal(*cfg.Header.Request, &request); err != nil {
			return t, fmt.Errorf("decode HttpRequest error: %w", err)
		}
		t.HTTPOptions.Host = request.Headers.Host
		if len(request.Path) > 0 {
			t.HTTPOptions.Path = request.Path[0]
		}
		t.HTTPOptions.Method = request.Method
	case "ws":
		var (
			path    string
			ed      int
			headers map[string]badoption.Listable[string]
		)
		if len(networkSettings) != 0 {
			cfg := WsNetworkConfig{}
			if err := json.Unmarshal(networkSettings, &cfg); err != nil {
				return t, fmt.Errorf("decode NetworkSettings error: %w", err)
			}
			u, err := url.Parse(cfg.Path)
			if err != nil {
				return t, fmt.Errorf("parse path error: %w", err)
			}
			path = u.Path
			ed, _ = strconv.Atoi(u.Query().Get("ed"))
			headers = make(map[string]badoption.Listable[string], len(cfg.Headers))
			for k, v := range cfg.Headers {
				headers[k] = badoption.Listable[string]{v}
			}
		}
		t.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:                path,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			MaxEarlyData:        uint32(ed),
			Headers:             headers,
		}
	case "grpc":
		cfg := GrpcNetworkConfig{}
		if len(networkSettings) != 0 {
			if err := json.Unmarshal(networkSettings, &cfg); err != nil {
				return t, fmt.Errorf("decode NetworkSettings error: %w", err)
			}
		}
		t.GRPCOptions = option.V2RayGRPCOptions{ServiceName: cfg.ServiceName}
	case "httpupgrade":
		cfg := HttpupgradeNetworkConfig{}
		if len(networkSettings) != 0 {
			if err := json.Unmarshal(networkSettings, &cfg); err != nil {
				return t, fmt.Errorf("decode NetworkSettings error: %w", err)
			}
		}
		t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Path: cfg.Path,
			Host: cfg.Host,
		}
	default:
		// Falling back to plain TCP here would bring the listener up on a
		// transport no client is speaking: the node looks healthy and every
		// connection fails, with nothing in the log pointing at the cause.
		return option.V2RayTransportOptions{}, fmt.Errorf(
			"the %q transport is not supported by the sing core (supported: tcp, ws, grpc, httpupgrade); serve this node with the xray core",
			network)
	}
	return t, nil
}

func buildMultiplex(c *conf.Options) *option.InboundMultiplexOptions {
	if c.SingOptions.Multiplex == nil {
		return nil
	}
	return &option.InboundMultiplexOptions{
		Enabled: c.SingOptions.Multiplex.Enabled,
		Padding: c.SingOptions.Multiplex.Padding,
		Brutal: &option.BrutalOptions{
			Enabled:  c.SingOptions.Multiplex.Brutal.Enabled,
			UpMbps:   c.SingOptions.Multiplex.Brutal.UpMbps,
			DownMbps: c.SingOptions.Multiplex.Brutal.DownMbps,
		},
	}
}

// getInboundOptions builds the sing-box inbound that serves a panel node.
//
// ShadowTLS and NaiveProxy are handled separately: ShadowTLS expands into two
// chained inbounds (see shadowtls.go) and NaiveProxy cannot be created before
// its first user is known (see naive.go).
func getInboundOptions(tag string, info *panel.NodeInfo, c *conf.Options) (option.Inbound, error) {
	listen, err := buildListenOptions(info, c)
	if err != nil {
		return option.Inbound{}, err
	}
	tls, err := buildTLSOptions(info, c)
	if err != nil {
		return option.Inbound{}, err
	}
	multiplex := buildMultiplex(c)

	in := option.Inbound{Tag: tag}
	switch info.Type {
	case "vmess", "vless":
		if info.VAllss == nil {
			return option.Inbound{}, fmt.Errorf("missing %s node settings", info.Type)
		}
		n := info.VAllss
		t, err := buildV2RayTransport(n.Network, n.NetworkSettings)
		if err != nil {
			return option.Inbound{}, err
		}
		if info.Type == "vless" {
			in.Type = "vless"
			in.Options = &option.VLESSInboundOptions{
				ListenOptions:              listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
				Transport:                  &t,
				Multiplex:                  multiplex,
			}
		} else {
			in.Type = "vmess"
			in.Options = &option.VMessInboundOptions{
				ListenOptions:              listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
				Transport:                  &t,
				Multiplex:                  multiplex,
			}
		}
	case "shadowsocks":
		if info.Shadowsocks == nil {
			return option.Inbound{}, fmt.Errorf("missing shadowsocks node settings")
		}
		in.Type = "shadowsocks"
		in.Options = buildShadowsocksOptions(listen, info.Shadowsocks.Cipher, info.Shadowsocks.ServerKey, multiplex)
	case "trojan":
		if info.Trojan == nil {
			return option.Inbound{}, fmt.Errorf("missing trojan node settings")
		}
		n := info.Trojan
		t, err := buildV2RayTransport(n.Network, n.NetworkSettings)
		if err != nil {
			return option.Inbound{}, err
		}
		trojanOption := &option.TrojanInboundOptions{
			ListenOptions:              listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
			Transport:                  &t,
			Multiplex:                  multiplex,
		}
		if c.SingOptions.FallBackConfigs != nil {
			fallback := c.SingOptions.FallBackConfigs.FallBack
			if fallbackPort, err := strconv.Atoi(fallback.ServerPort); err == nil {
				trojanOption.Fallback = &option.ServerOptions{
					Server:     fallback.Server,
					ServerPort: uint16(fallbackPort),
				}
			}
			fallbackForALPN := make(map[string]*option.ServerOptions, len(c.SingOptions.FallBackConfigs.FallBackForALPN))
			if err := processFallback(c, fallbackForALPN); err == nil {
				trojanOption.FallbackForALPN = fallbackForALPN
			}
		}
		in.Type = "trojan"
		in.Options = trojanOption
	case "anytls":
		if info.AnyTls == nil {
			return option.Inbound{}, fmt.Errorf("missing anytls node settings")
		}
		in.Type = "anytls"
		in.Options = &option.AnyTLSInboundOptions{
			ListenOptions:              listen,
			PaddingScheme:              info.AnyTls.PaddingScheme,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
	case "tuic":
		if info.Tuic == nil {
			return option.Inbound{}, fmt.Errorf("missing tuic node settings")
		}
		// TUIC runs over QUIC, so the TLS layer must advertise h3.
		tls.ALPN = append(tls.ALPN, "h3")
		timings, err := tuicTimings(info.Tuic, c)
		if err != nil {
			return option.Inbound{}, err
		}
		in.Type = "tuic"
		in.Options = &option.TUICInboundOptions{
			ListenOptions:              listen,
			CongestionControl:          timings.congestionControl,
			AuthTimeout:                badoption.Duration(timings.authTimeout),
			Heartbeat:                  badoption.Duration(timings.heartbeat),
			ZeroRTTHandshake:           info.Tuic.ZeroRTTHandshake,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
	case "hysteria":
		if info.Hysteria == nil {
			return option.Inbound{}, fmt.Errorf("missing hysteria node settings")
		}
		tuning := hysteriaQUICTuning(info.Hysteria, c)
		in.Type = "hysteria"
		in.Options = &option.HysteriaInboundOptions{
			ListenOptions:              listen,
			UpMbps:                     info.Hysteria.UpMbps,
			DownMbps:                   info.Hysteria.DownMbps,
			Obfs:                       info.Hysteria.Obfs,
			ReceiveWindowConn:          tuning.receiveWindowConn,
			ReceiveWindowClient:        tuning.receiveWindowClient,
			MaxConnClient:              tuning.maxConnClient,
			DisableMTUDiscovery:        tuning.disableMTUDiscovery,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
	case "hysteria2":
		if info.Hysteria2 == nil {
			return option.Inbound{}, fmt.Errorf("missing hysteria2 node settings")
		}
		masquerade, err := buildHysteria2Masquerade(info.Hysteria2, c)
		if err != nil {
			return option.Inbound{}, err
		}
		in.Type = "hysteria2"
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:              listen,
			UpMbps:                     info.Hysteria2.UpMbps,
			DownMbps:                   info.Hysteria2.DownMbps,
			IgnoreClientBandwidth:      info.Hysteria2.IgnoreClientBandwidth,
			Obfs:                       buildHysteria2Obfs(info.Hysteria2),
			Masquerade:                 masquerade,
			BrutalDebug:                hysteriaOptions(c).BrutalDebug,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
		}
	default:
		return option.Inbound{}, fmt.Errorf("unsupported node type: %s", info.Type)
	}
	return in, nil
}

// hysteriaOptions returns the node-local Hysteria settings, or an empty set
// when the deployment configured none.
func hysteriaOptions(c *conf.Options) conf.HysteriaOptions {
	if c.SingOptions == nil || c.SingOptions.HysteriaOptions == nil {
		return conf.HysteriaOptions{}
	}
	return *c.SingOptions.HysteriaOptions
}

// tuicSettings are the TUIC knobs resolved from the panel and the local config.
type tuicSettings struct {
	congestionControl string
	authTimeout       time.Duration
	heartbeat         time.Duration
}

// tuicTimings resolves the TUIC connection settings. The panel wins on every
// field it sends; the local config fills the rest, which is what lets an
// operator tune heartbeat and auth timeout on a panel that cannot express
// them.
func tuicTimings(n *panel.TuicNode, c *conf.Options) (tuicSettings, error) {
	settings := tuicSettings{
		congestionControl: n.CongestionControl,
		authTimeout:       time.Duration(n.AuthTimeout),
		heartbeat:         time.Duration(n.Heartbeat),
	}
	if c.SingOptions == nil || c.SingOptions.TuicOptions == nil {
		return settings, nil
	}
	o := c.SingOptions.TuicOptions
	if settings.congestionControl == "" {
		settings.congestionControl = o.CongestionControl
	}
	if settings.authTimeout == 0 {
		parsed, err := parseConfigDuration(o.AuthTimeout, "TuicOptions.AuthTimeout")
		if err != nil {
			return tuicSettings{}, err
		}
		settings.authTimeout = parsed
	}
	if settings.heartbeat == 0 {
		parsed, err := parseConfigDuration(o.Heartbeat, "TuicOptions.Heartbeat")
		if err != nil {
			return tuicSettings{}, err
		}
		settings.heartbeat = parsed
	}
	return settings, nil
}

// parseConfigDuration reads a duration out of the node config. An empty value
// means "not set" rather than zero, so the core keeps its own default.
func parseConfigDuration(value, field string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration: %w", field, value, err)
	}
	return parsed, nil
}

// hysteriaTuning are the QUIC flow control knobs of a Hysteria v1 node.
type hysteriaTuning struct {
	receiveWindowConn   uint64
	receiveWindowClient uint64
	maxConnClient       int
	disableMTUDiscovery bool
}

// hysteriaQUICTuning resolves the v1 flow control settings, panel first. Zero
// stays zero: sing-box reads that as "use my default".
func hysteriaQUICTuning(n *panel.HysteriaNode, c *conf.Options) hysteriaTuning {
	tuning := hysteriaTuning{
		receiveWindowConn:   n.ReceiveWindowConn,
		receiveWindowClient: n.ReceiveWindowClient,
		maxConnClient:       n.MaxConnClient,
		disableMTUDiscovery: n.DisableMTUDiscovery,
	}
	o := hysteriaOptions(c)
	if tuning.receiveWindowConn == 0 {
		tuning.receiveWindowConn = o.ReceiveWindowConn
	}
	if tuning.receiveWindowClient == 0 {
		tuning.receiveWindowClient = o.ReceiveWindowClient
	}
	if tuning.maxConnClient == 0 {
		tuning.maxConnClient = o.MaxConnClient
	}
	if !tuning.disableMTUDiscovery {
		tuning.disableMTUDiscovery = o.DisableMTUDiscovery
	}
	return tuning
}

// buildHysteria2Masquerade resolves what the node answers ordinary HTTP
// requests with.
//
// The panel's value is passed to sing-box untouched, so both forms it accepts
// work: a bare URL string ("https://example.com", "file:///var/www") and the
// full object. The local config only offers the URL form, which is what an
// operator writes by hand.
func buildHysteria2Masquerade(n *panel.Hysteria2Node, c *conf.Options) (*option.Hysteria2Masquerade, error) {
	raw := n.Masquerade
	if len(raw) == 0 {
		configured := strings.TrimSpace(hysteriaOptions(c).Masquerade)
		if configured == "" {
			return nil, nil
		}
		encoded, err := json.Marshal(configured)
		if err != nil {
			return nil, fmt.Errorf("encode masquerade %q: %w", configured, err)
		}
		raw = encoded
	}
	masquerade := &option.Hysteria2Masquerade{}
	if err := json.Unmarshal(raw, masquerade); err != nil {
		return nil, fmt.Errorf("decode masquerade error: %w", err)
	}
	if masquerade.Type == "" {
		return nil, nil
	}
	return masquerade, nil
}

// buildHysteria2Obfs reads the panel's obfuscation settings. Panels differ on
// whether they send the password in "obfs" or "obfs-password", so a lone
// "obfs" value is treated as a Salamander password.
func buildHysteria2Obfs(n *panel.Hysteria2Node) *option.Hysteria2Obfs {
	switch {
	case n.ObfsType != "" && n.ObfsPassword != "":
		return &option.Hysteria2Obfs{Type: n.ObfsType, Password: n.ObfsPassword}
	case n.ObfsType != "":
		return &option.Hysteria2Obfs{Type: "salamander", Password: n.ObfsType}
	default:
		return nil
	}
}

// buildShadowsocksOptions creates a Shadowsocks inbound seeded with a single
// throwaway user. sing-box needs a well-formed user list up front; the real
// users arrive through AddUsers.
func buildShadowsocksOptions(listen option.ListenOptions, cipher, serverKey string, multiplex *option.InboundMultiplexOptions) *option.ShadowsocksInboundOptions {
	opts := &option.ShadowsocksInboundOptions{
		ListenOptions: listen,
		Method:        cipher,
		Multiplex:     multiplex,
	}
	p := make([]byte, shadowsocksKeyLength(cipher))
	_, _ = rand.Read(p)
	randomPasswd := string(p)
	if strings.Contains(cipher, "2022") {
		opts.Password = serverKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
	}
	opts.Users = []option.ShadowsocksUser{{Password: randomPasswd}}
	return opts
}

// buildNaiveOptions creates the NaiveProxy inbound for the supplied users.
// Naive refuses to start without at least one user, which is why the inbound
// is (re)built from the current user set rather than mutated in place.
func buildNaiveOptions(info *panel.NodeInfo, c *conf.Options, users []auth.User) (*option.NaiveInboundOptions, error) {
	listen, err := buildListenOptions(info, c)
	if err != nil {
		return nil, err
	}
	tls, err := buildTLSOptions(info, c)
	if err != nil {
		return nil, err
	}
	if !tls.Enabled {
		return nil, fmt.Errorf("naive requires TLS: set a CertConfig with a certificate")
	}
	// Naive is an HTTP CONNECT proxy; without these the client's ALPN
	// negotiation fails before authentication is ever attempted.
	tls.ALPN = append(tls.ALPN, "h2", "http/1.1")

	network := info.Naive.Network
	if c.SingOptions.NaiveOptions != nil && c.SingOptions.NaiveOptions.Network != "" {
		network = c.SingOptions.NaiveOptions.Network
	}
	// A network list carrying udp is what makes sing-box bring up naive's
	// HTTP/3 listener on the same port. That listener shares this TLS config,
	// and sing-quic only defaults the ALPN to h3 when none was set at all — so
	// without this the QUIC handshake dies on `no application protocol` and the
	// listener answers nothing. The cost is that the TCP listener would also
	// select h3 if a client offered it there, which no real client does.
	if naiveNetworkCarriesUDP(network) {
		tls.ALPN = append(tls.ALPN, "h3")
	}
	return &option.NaiveInboundOptions{
		ListenOptions:              listen,
		Users:                      users,
		Network:                    option.NetworkList(network),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &tls},
	}, nil
}

// naiveNetworkCarriesUDP mirrors option.NetworkList.Build: an empty list means
// both networks, which is the default a panel node arrives with.
func naiveNetworkCarriesUDP(network string) bool {
	if network == "" {
		return true
	}
	for _, entry := range strings.Split(network, "\n") {
		if strings.TrimSpace(entry) == N.NetworkUDP {
			return true
		}
	}
	return false
}
