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
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Common      *CommonNode
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
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
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)

	node.Common = cm
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil

	return node, nil
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
