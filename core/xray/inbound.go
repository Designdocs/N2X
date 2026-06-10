package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// BuildInbound build Inbound config for different protocol
func buildInbound(option *conf.Options, nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	var network string
	switch nodeInfo.Type {
	case "vmess", "vless":
		err = buildV2ray(option, nodeInfo, in)
		network = nodeInfo.VAllss.Network
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
		network = "tcp"
	case "trojan":
		err = buildTrojan(option, nodeInfo, in)
		if nodeInfo.Trojan.Network != "" {
			network = nodeInfo.Trojan.Network
		} else {
			network = "tcp"
		}
	case "shadowsocks":
		err = buildShadowsocks(option, nodeInfo, in)
		network = "tcp"
	default:
		return nil, fmt.Errorf("unsupported node type: %s, only support: vmess, vless, anytls, trojan, shadowsocks", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Common.ServerPort),
				To:   uint32(nodeInfo.Common.ServerPort),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(option.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: coreConf.StringList{"http", "tls"},
	}
	if option.XrayOptions.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	in.SniffingConfig = sniffingConfig
	switch network {
	case "tcp":
		if in.StreamSetting.TCPSettings != nil {
			in.StreamSetting.TCPSettings.AcceptProxyProtocol = option.XrayOptions.EnableProxyProtocol
		} else {
			tcpSetting := &coreConf.TCPConfig{
				AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			} //Enable proxy protocol
			in.StreamSetting.TCPSettings = tcpSetting
		}
	case "ws":
		if in.StreamSetting.WSSettings != nil {
			in.StreamSetting.WSSettings.AcceptProxyProtocol = option.XrayOptions.EnableProxyProtocol
		} else {
			in.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
				AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			} //Enable proxy protocol
		}
	default:
		socketConfig := &coreConf.SocketConfig{
			AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			TFO:                 option.XrayOptions.EnableTFO,
		} //Enable proxy protocol
		in.StreamSetting.SocketSettings = socketConfig
	}
	// Set TLS or Reality settings
	switch nodeInfo.Security {
	case panel.Tls:
		tlsConfig, err := buildInboundTLSConfig(option, nodeInfo)
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil {
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = tlsConfig
		}
	case panel.Reality:
		// Reality
		in.StreamSetting.Security = "reality"
		v := nodeInfo.VAllss
		dest := v.TlsSettings.Dest
		if dest == "" {
			dest = v.TlsSettings.ServerName
		}
		xver := v.TlsSettings.Xver
		if xver == 0 {
			xver = v.RealityConfig.Xver
		}
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%s",
			dest,
			v.TlsSettings.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		mtd, _ := time.ParseDuration(v.RealityConfig.MaxTimeDiff)
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:         d,
			Xver:         xver,
			Show:         false,
			ServerNames:  []string{v.TlsSettings.ServerName},
			PrivateKey:   v.TlsSettings.PrivateKey,
			MinClientVer: v.RealityConfig.MinClientVer,
			MaxClientVer: v.RealityConfig.MaxClientVer,
			MaxTimeDiff:  uint64(mtd.Microseconds()),
			ShortIds:     []string{v.TlsSettings.ShortId},
			Mldsa65Seed:  v.TlsSettings.Mldsa65Seed,
		}
	default:
		break
	}
	in.Tag = tag
	return in.Build()
}

func buildInboundTLSConfig(option *conf.Options, nodeInfo *panel.NodeInfo) (*coreConf.TLSConfig, error) {
	certConfig := getInboundCertConfig(option, nodeInfo)
	if certConfig == nil {
		return nil, errors.New("the CertConfig is not vail")
	}

	switch certConfig.CertMode {
	case "none", "":
		return nil, nil
	}

	tlsConfig := &coreConf.TLSConfig{
		Certs: []*coreConf.TLSCertConfig{
			{
				CertFile:     certConfig.CertFile,
				KeyFile:      certConfig.KeyFile,
				OcspStapling: 3600,
			},
		},
		RejectUnknownSNI: certConfig.RejectUnknownSni,
	}

	echConfig, err := buildInboundECHConfig(nodeInfo)
	if err != nil {
		return nil, err
	}
	if echConfig != nil {
		tlsConfig.ECHServerKeys = echConfig.ServerKeys
	}

	return tlsConfig, nil
}

func getInboundCertConfig(option *conf.Options, nodeInfo *panel.NodeInfo) *conf.CertConfig {
	if nodeInfo != nil && nodeInfo.CertConfig != nil && nodeInfo.CertConfig.CertMode != "" {
		return nodeInfo.CertConfig
	}
	if option == nil {
		return nil
	}
	return option.CertConfig
}

type inboundECHConfig struct {
	ServerKeys string
}

func buildInboundECHConfig(nodeInfo *panel.NodeInfo) (*inboundECHConfig, error) {
	echSettings := getInboundECHSettings(nodeInfo)
	if echSettings == nil || !echSettings.Enabled {
		return nil, nil
	}

	clientConfig, err := normalizeECHValue(echSettings.Config, "ECH CONFIGS")
	if err != nil {
		return nil, err
	}
	serverKeys, err := normalizeECHValue(echSettings.Key, "ECH KEYS")
	if err != nil {
		return nil, err
	}

	switch {
	case clientConfig == "" && serverKeys == "":
		return nil, nil
	case clientConfig == "":
		return nil, errors.New("ech server key requires matching client config")
	case serverKeys == "":
		return nil, errors.New("ech client config requires matching server key")
	}

	return &inboundECHConfig{ServerKeys: serverKeys}, nil
}

func getInboundECHSettings(nodeInfo *panel.NodeInfo) *panel.ECHSettings {
	switch nodeInfo.Type {
	case "vmess", "vless":
		if nodeInfo.VAllss == nil {
			return nil
		}
		return nodeInfo.VAllss.TlsSettings.Ech
	case "trojan":
		if nodeInfo.Trojan == nil {
			return nil
		}
		return nodeInfo.Trojan.TlsSettings.Ech
	case "anytls":
		if nodeInfo.AnyTls == nil {
			return nil
		}
		return nodeInfo.AnyTls.TlsSettings.Ech
	default:
		return nil
	}
}

func normalizeECHValue(value string, expectedPEMType string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}

	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return "", fmt.Errorf("decode %s pem error", strings.ToLower(expectedPEMType))
		}
		if expectedPEMType != "" && block.Type != expectedPEMType {
			return "", fmt.Errorf("unexpected pem block type %q", block.Type)
		}
		return base64.StdEncoding.EncodeToString(block.Bytes), nil
	}

	return strings.Join(strings.Fields(trimmed), ""), nil
}

func buildV2ray(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.VAllss
	if nodeInfo.Type == "vless" {
		//Set vless
		inbound.Protocol = "vless"
		if config.XrayOptions.EnableFallback {
			// Set fallback
			fallbackConfigs, err := buildVlessFallbacks(config.XrayOptions.FallBackConfigs)
			if err != nil {
				return err
			}
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: "none",
				Fallbacks:  fallbackConfigs,
			})
			if err != nil {
				return fmt.Errorf("marshal vless fallback config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		} else {
			var err error
			decryption := "none"
			if nodeInfo.VAllss.Encryption != "" {
				switch nodeInfo.VAllss.Encryption {
				case "mlkem768x25519plus":
					encSettings := nodeInfo.VAllss.EncryptionSettings
					parts := []string{
						"mlkem768x25519plus",
						encSettings.Mode,
						encSettings.Ticket,
					}
					if encSettings.ServerPadding != "" {
						parts = append(parts, encSettings.ServerPadding)
					}
					parts = append(parts, encSettings.PrivateKey)
					decryption = strings.Join(parts, ".")
				default:
					return fmt.Errorf("vless decryption method %s is not support", nodeInfo.VAllss.Encryption)
				}
			}
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: decryption,
			})
			if err != nil {
				return fmt.Errorf("marshal vless config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		}
	} else {
		// Set vmess
		inbound.Protocol = "vmess"
		var err error
		s, err := json.Marshal(&coreConf.VMessInboundConfig{})
		if err != nil {
			return fmt.Errorf("marshal vmess settings error: %s", err)
		}
		inbound.Settings = (*json.RawMessage)(&s)
	}
	if len(v.NetworkSettings) == 0 {
		return nil
	}

	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Trojan
	if config.XrayOptions.EnableFallback {
		// Set fallback
		fallbackConfigs, err := buildTrojanFallbacks(config.XrayOptions.FallBackConfigs)
		if err != nil {
			return err
		}
		s, err := json.Marshal(&coreConf.TrojanServerConfig{
			Fallbacks: fallbackConfigs,
		})
		inbound.Settings = (*json.RawMessage)(&s)
		if err != nil {
			return fmt.Errorf("marshal trojan fallback config error: %s", err)
		}
	} else {
		s := []byte("{}")
		inbound.Settings = (*json.RawMessage)(&s)
	}
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: nodeInfo.AnyTls.PaddingScheme,
	}
	rawSettings, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&rawSettings)
	return nil
}

func buildShadowsocks(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Shadowsocks
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildVlessFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}
	vlessFallBacks := make([]*coreConf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {
		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}
		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		vlessFallBacks[i] = &coreConf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*coreConf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		trojanFallBacks[i] = &coreConf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
