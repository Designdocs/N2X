package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/Designdocs/N2X/conf"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	RawDNS       RawDNS
	Rules        Rules

	// origin
	VAllss      *VAllssNode
	AnyTls      *AnyTlsNode
	ArtX        *ArtXNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	ShadowTLS   *ShadowTLSNode
	Naive       *NaiveNode
	Common      *CommonNode
	CertConfig  *conf.CertConfig
}

type CommonNode struct {
	Host       string           `json:"host"`
	ServerPort int              `json:"server_port"`
	ServerName string           `json:"server_name"`
	Routes     []Route          `json:"routes"`
	BaseConfig *BaseConfig      `json:"base_config"`
	CertConfig *conf.CertConfig `json:"cert_config"`
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	CommonNode
	Tls                 int             `json:"tls"`
	TlsSettings         TlsSettings     `json:"tls_settings"`
	TlsSettingsBack     *TlsSettings    `json:"tlsSettings"`
	Network             string          `json:"network"`
	NetworkSettings     json.RawMessage `json:"network_settings"`
	NetworkSettingsBack json.RawMessage `json:"networkSettings"`
	Encryption          string          `json:"encryption"`
	EncryptionSettings  EncSettings     `json:"encryption_settings"`
	ServerName          string          `json:"server_name"`

	// vless only
	Flow          string        `json:"flow"`
	RealityConfig RealityConfig `json:"-"`
}

type TlsSettings struct {
	ServerName    string       `json:"server_name"`
	AllowInsecure bool         `json:"allow_insecure"`
	Dest          string       `json:"dest"`
	ServerPort    string       `json:"server_port"`
	ShortId       string       `json:"short_id"`
	PrivateKey    string       `json:"private_key"`
	Mldsa65Seed   string       `json:"mldsa65Seed"`
	Xver          uint64       `json:"xver,string"`
	Ech           *ECHSettings `json:"ech"`
}

type ECHSettings struct {
	Enabled         bool   `json:"enabled"`
	Config          string `json:"config"`
	QueryServerName string `json:"query_server_name"`
	Key             string `json:"key"`
	KeyPath         string `json:"key_path"`
	ConfigPath      string `json:"config_path"`
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
	TlsSettings     TlsSettings     `json:"tls_settings"`
	TlsSettingsBack *TlsSettings    `json:"tlsSettings"`
}

type AnyTlsNode struct {
	CommonNode
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
	PaddingScheme   []string     `json:"padding_scheme,omitempty"`
}

type TuicNode struct {
	CommonNode
	// Version is the TUIC generation the panel pinned the node to. sing-box
	// implements v5 only; zero means the panel did not say.
	Version           int          `json:"version"`
	CongestionControl string       `json:"congestion_control"`
	ZeroRTTHandshake  bool         `json:"zero_rtt_handshake"`
	TlsSettings       TlsSettings  `json:"tls_settings"`
	TlsSettingsBack   *TlsSettings `json:"tlsSettings"`
}

type HysteriaNode struct {
	CommonNode
	UpMbps          int          `json:"up_mbps"`
	DownMbps        int          `json:"down_mbps"`
	Obfs            string       `json:"obfs"`
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
}

type Hysteria2Node struct {
	CommonNode
	IgnoreClientBandwidth bool         `json:"ignore_client_bandwidth"`
	UpMbps                int          `json:"up_mbps"`
	DownMbps              int          `json:"down_mbps"`
	ObfsType              string       `json:"obfs"`
	ObfsPassword          string       `json:"obfs-password"`
	TlsSettings           TlsSettings  `json:"tls_settings"`
	TlsSettingsBack       *TlsSettings `json:"tlsSettings"`
}

// ShadowTLSNode carries the panel-supplied ShadowTLS parameters.
//
// A ShadowTLS node is served as two chained sing-box inbounds: the public
// ShadowTLS listener performs the TLS camouflage handshake against a real
// upstream site, then hands the decrypted stream to an internal Shadowsocks
// inbound (the "detour") which owns per-user authentication and traffic
// accounting. The Cipher/ServerKey fields therefore configure that inner
// Shadowsocks layer, exactly as they would on a plain shadowsocks node.
type ShadowTLSNode struct {
	CommonNode
	Version     int                `json:"version"`
	Password    string             `json:"password"`
	Handshake   ShadowTLSHandshake `json:"handshake"`
	StrictMode  bool               `json:"strict_mode"`
	WildcardSNI string             `json:"wildcard_sni"`

	// Inner Shadowsocks detour settings.
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

// ShadowTLSHandshake is the upstream server the ShadowTLS listener relays the
// camouflage handshake to. It must be a real TLS 1.3 site.
type ShadowTLSHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// NaiveNode carries the panel-supplied NaiveProxy parameters. Naive always
// requires TLS: it is an HTTP/2 (and optionally HTTP/3) CONNECT proxy whose
// cover traffic is indistinguishable from ordinary HTTPS.
type NaiveNode struct {
	CommonNode
	// Network restricts the listener to "tcp" (HTTP/2 only) or "udp"
	// (HTTP/3 only). Empty means both.
	Network         string       `json:"network"`
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
}

type ArtXNode struct {
	CommonNode
	PublicHost      string       `json:"public_host"`
	PublicPort      int          `json:"public_port"`
	Underlay        string       `json:"underlay"`
	WireVersion     int          `json:"wire_version"`
	FlowControl     string       `json:"flow_control"`
	Profile         string       `json:"profile"`
	ProfileVersion  int          `json:"profile_version"`
	UDP             bool         `json:"udp"`
	UDPMode         string       `json:"udp_mode"`
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
	PaddingScheme   []string     `json:"padding_scheme,omitempty"`
	Fallback        ArtXFallback `json:"fallback"`
	Behavior        ArtXBehavior `json:"behavior"`
}

const (
	ArtXFlowControlLegacy      = "legacy"
	ArtXFlowControlHighLatency = "high_latency"
	ArtXHighLatencyWindowScale = 4
)

type ArtXFallback struct {
	Enabled bool   `json:"enabled"`
	Origin  string `json:"origin"`
}

type ArtXBehavior struct {
	Padding       string `json:"padding"`
	Keepalive     string `json:"keepalive"`
	ErrorResponse string `json:"error_response"`
}

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

type Rules struct {
	Regexp   []string
	Protocol []string
}

var xhttpObjectLikeKeys = map[string]struct{}{
	"downloadSettings":  {},
	"extra":             {},
	"headers":           {},
	"realitySettings":   {},
	"sockopt":           {},
	"splithttpSettings": {},
	"tlsSettings":       {},
	"xhttpSettings":     {},
	"xmux":              {},
}

// hysteriaVersion reads the protocol generation out of a node config payload.
// A missing or unparsable version yields 0 so the caller can fall back to the
// configured node type rather than guessing.
func hysteriaVersion(body []byte) int {
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return 0
	}
	if probe.Version < 0 {
		return 0
	}
	return probe.Version
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/api/v1/server/UniProxy/config"
	c.etagMu.Lock()
	currentEtag := c.nodeEtag
	currentHash := c.responseBodyHash
	c.etagMu.Unlock()

	r, err := c.client.
		R().
		SetHeader("If-None-Match", currentEtag).
		ForceContentType("application/json").
		Get(path)

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if currentHash == newBodyHash {
		return nil, nil
	}
	c.etagMu.Lock()
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	c.etagMu.Unlock()

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch c.NodeType {
	case "vmess", "vless":
		rsp := &VAllssNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode v2ray params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
			rsp.TlsSettingsBack = nil
		}
		rsp.NetworkSettings, err = normalizeLegacyXHTTPSettings(rsp.Network, rsp.NetworkSettings)
		if err != nil {
			return nil, fmt.Errorf("normalize xhttp settings error: %s", err)
		}
		cm = &rsp.CommonNode
		node.VAllss = rsp
		node.Security = node.VAllss.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trojan params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode anytls params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		node.Security = Tls
	case "artx":
		rsp := &ArtXNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode artx params error: %s", err)
		}
		normalizeArtXNode(rsp)
		cm = &rsp.CommonNode
		node.ArtX = rsp
		node.Security = Tls
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode tuic params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
			rsp.TlsSettingsBack = nil
		}
		// sing-box implements TUIC v5 only. Serving v5 to a node the panel
		// pinned to an older generation would fail every client handshake
		// with nothing in the log explaining why.
		if rsp.Version != 0 && rsp.Version < 5 {
			return nil, fmt.Errorf("tuic v%d is not supported, only v5", rsp.Version)
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "hysteria", "hysteria2":
		// Panels model Hysteria as one node type carrying a version field
		// rather than as two types: 1 is Hysteria, 2 is Hysteria2. They are
		// different wire protocols served by different inbounds, so the
		// version decides which one to build and node.Type is rewritten to
		// match — the core selector reads it to route the node.
		version := hysteriaVersion(r.Body())
		if version == 0 {
			// A panel that models the generation as its own node type sends
			// no version; fall back to what the operator configured.
			version = 1
			if c.NodeType == "hysteria2" {
				version = 2
			}
		}
		if version >= 2 {
			rsp := &Hysteria2Node{}
			err = json.Unmarshal(r.Body(), rsp)
			if err != nil {
				return nil, fmt.Errorf("decode hysteria2 params error: %s", err)
			}
			if rsp.TlsSettingsBack != nil {
				rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
				rsp.TlsSettingsBack = nil
			}
			cm = &rsp.CommonNode
			node.Hysteria2 = rsp
			node.Type = "hysteria2"
		} else {
			rsp := &HysteriaNode{}
			err = json.Unmarshal(r.Body(), rsp)
			if err != nil {
				return nil, fmt.Errorf("decode hysteria params error: %s", err)
			}
			if rsp.TlsSettingsBack != nil {
				rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
				rsp.TlsSettingsBack = nil
			}
			cm = &rsp.CommonNode
			node.Hysteria = rsp
			node.Type = "hysteria"
		}
		node.Security = Tls
	case "shadowtls":
		rsp := &ShadowTLSNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowtls params error: %s", err)
		}
		normalizeShadowTLSNode(rsp)
		cm = &rsp.CommonNode
		node.ShadowTLS = rsp
		// ShadowTLS terminates the camouflage handshake itself and the inner
		// Shadowsocks layer needs no certificate of its own.
		node.Security = None
	case "naive":
		rsp := &NaiveNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode naive params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = mergeLegacyTLSSettings(rsp.TlsSettings, rsp.TlsSettingsBack)
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Naive = rsp
		node.Security = Tls
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	// parse rules and dns
	for i := range cm.Routes {
		var matchs []string
		if _, ok := cm.Routes[i].Match.(string); ok {
			matchs = strings.Split(cm.Routes[i].Match.(string), ",")
		} else if _, ok = cm.Routes[i].Match.([]string); ok {
			matchs = cm.Routes[i].Match.([]string)
		} else {
			temp := cm.Routes[i].Match.([]interface{})
			matchs = make([]string, len(temp))
			for i := range temp {
				matchs[i] = temp[i].(string)
			}
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					// protocol
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					// domain
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		}
	}

	// set interval
	//
	// base_config is optional: a panel that omits it used to crash the agent
	// here on a nil dereference. Fall back to the 60s that both X-Board and
	// V2board default to. A present-but-zero value is left alone, since
	// node/task.go already treats zero as "keep the current interval".
	const defaultInterval = 60 * time.Second
	node.PushInterval = defaultInterval
	node.PullInterval = defaultInterval
	if cm.BaseConfig != nil {
		node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
		node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)
	}
	node.CertConfig = cm.CertConfig

	node.Common = cm
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil
	cm.CertConfig = nil

	return node, nil
}

func normalizeArtXNode(node *ArtXNode) {
	if node.TlsSettingsBack != nil {
		node.TlsSettings = mergeLegacyTLSSettings(node.TlsSettings, node.TlsSettingsBack)
		node.TlsSettingsBack = nil
	}
	if strings.TrimSpace(node.Underlay) == "" {
		node.Underlay = "anytls"
	}
	node.FlowControl = strings.TrimSpace(node.FlowControl)
	if node.FlowControl == "" || node.Underlay != "artx-wire" {
		node.FlowControl = ArtXFlowControlLegacy
	}
	if strings.TrimSpace(node.Profile) == "" {
		node.Profile = "balanced"
	}
	if node.ProfileVersion < 1 {
		node.ProfileVersion = 1
	}
	if strings.TrimSpace(node.UDPMode) == "" || !node.UDP || node.Underlay != "artx-wire" {
		node.UDPMode = "compat"
	}
}

// normalizeShadowTLSNode fills in the defaults for the fields a panel is not
// guaranteed to send. ShadowTLS is not part of the stock X-Board node schema,
// so a partially populated payload is the common case rather than an error.
func normalizeShadowTLSNode(node *ShadowTLSNode) {
	// v3 is the only version that resists the active probing attacks v1 and
	// v2 are known to be vulnerable to, so it is the default.
	if node.Version < 1 || node.Version > 3 {
		node.Version = 3
	}
	if strings.TrimSpace(node.Cipher) == "" {
		node.Cipher = "2022-blake3-aes-128-gcm"
	}
	if strings.TrimSpace(node.Handshake.Server) == "" {
		// Fall back to the node's own advertised name so the camouflage
		// target at least resolves rather than failing every handshake.
		if strings.TrimSpace(node.ServerName) != "" {
			node.Handshake.Server = node.ServerName
		} else {
			node.Handshake.Server = node.Host
		}
	}
	if node.Handshake.ServerPort == 0 {
		node.Handshake.ServerPort = 443
	}
	switch strings.ToLower(strings.TrimSpace(node.WildcardSNI)) {
	case "authed", "all":
		node.WildcardSNI = strings.ToLower(strings.TrimSpace(node.WildcardSNI))
	default:
		node.WildcardSNI = "off"
	}
}

func mergeLegacyTLSSettings(current TlsSettings, legacy *TlsSettings) TlsSettings {
	if legacy == nil {
		return current
	}
	return *legacy
}

func normalizeLegacyXHTTPSettings(network string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || (network != "xhttp" && network != "splithttp") {
		return raw, nil
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	normalized, changed := normalizeLegacyXHTTPValue(payload)
	if !changed {
		return raw, nil
	}

	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func normalizeLegacyXHTTPValue(value any) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		changed := false
		for key, child := range typed {
			if shouldNormalizeObjectLikeArray(key, child) {
				typed[key] = map[string]any{}
				changed = true
				child = typed[key]
			}
			normalized, childChanged := normalizeLegacyXHTTPValue(child)
			if childChanged {
				typed[key] = normalized
				changed = true
			}
		}
		return typed, changed
	case []any:
		changed := false
		for index, child := range typed {
			normalized, childChanged := normalizeLegacyXHTTPValue(child)
			if childChanged {
				typed[index] = normalized
				changed = true
			}
		}
		return typed, changed
	default:
		return value, false
	}
}

func shouldNormalizeObjectLikeArray(key string, value any) bool {
	if _, ok := xhttpObjectLikeKeys[key]; !ok {
		return false
	}
	items, ok := value.([]any)
	return ok && len(items) == 0
}

func intervalToTime(i interface{}) time.Duration {
	// reflect.TypeOf(nil) is nil, so Kind() below would panic on a JSON null
	// or an absent field.
	if i == nil {
		return 0
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}
