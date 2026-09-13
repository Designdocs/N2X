package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var httpSchemes, wsSchemes = []string{"http", "https"}, []string{"ws", "wss"}

func (v *validator) checkNodes(nodes []NodeConfig, cores map[string]string) {
	if len(nodes) == 0 {
		v.add("Nodes", "at least one node is required")
		return
	}
	identities := map[string]int{}
	certFiles := map[string]certFileUse{}
	for i := range nodes {
		node := &nodes[i]
		base := indexPath("Nodes", i)
		apiPath, optPath := v.nodePaths(base)

		v.checkAPI(apiPath, &node.ApiConfig)
		v.checkCoreSelection(optPath, &node.Options, cores)
		v.checkOptions(optPath, &node.Options, cores)

		identity := nodeIdentity(&node.ApiConfig)
		if first, dup := identities[identity]; dup {
			v.add(base, "same panel node as Nodes[%d] (ApiHost, NodeID and NodeType all match); list each node once", first)
		} else {
			identities[identity] = i
		}
		v.checkSharedCertFiles(optPath+".CertConfig", i, node.Options.CertConfig, certFiles)
	}
}

// nodePaths returns where a node's API settings and options live in the
// file, so issues point at the keys the operator actually wrote.
func (v *validator) nodePaths(base string) (string, string) {
	apiPath, optPath := base, base
	body := v.nodeBodies[base]
	if _, ok := lookupKey(body, "ApiConfig"); ok {
		apiPath = base + ".ApiConfig"
	}
	if _, ok := lookupKey(body, "Options"); ok {
		optPath = base + ".Options"
	}
	return apiPath, optPath
}

func (v *validator) checkAPI(path string, a *ApiConfig) {
	v.checkURL(path+".ApiHost", a.APIHost, httpSchemes)
	if strings.TrimSpace(a.Key) == "" {
		v.add(path+".ApiKey", "required")
	}
	if a.NodeID <= 0 {
		v.add(path+".NodeID", "must be a positive integer, got %d", a.NodeID)
	}
	switch nodeType := strings.ToLower(a.NodeType); {
	case nodeType == "":
		v.add(path+".NodeType", "required (use %s)", quoteList(panelNodeTypes))
	case !slices.Contains(panelNodeTypes, nodeType):
		v.add(path+".NodeType", "unsupported node type %q (use %s)", a.NodeType, quoteList(panelNodeTypes))
	}
	nonNegative(v, path+".Timeout", a.Timeout)
	v.checkIP(path+".ApiSendIP", a.APISendIP)
	if a.WebSocket.URL != "" {
		v.checkURL(path+".WebSocket.URL", a.WebSocket.URL, wsSchemes)
	}
}

func nodeIdentity(a *ApiConfig) string {
	nodeType := strings.ToLower(a.NodeType)
	if nodeType == "v2ray" {
		nodeType = "vmess"
	}
	host := strings.TrimRight(strings.TrimSpace(a.APIHost), "/")
	return fmt.Sprintf("%s|%d|%s", host, a.NodeID, nodeType)
}

// checkCoreSelection checks that the core a node asks for exists. Options
// drops a Core it does not recognise, so the written value is read back from
// the undecoded options.
func (v *validator) checkCoreSelection(path string, o *Options, cores map[string]string) {
	core := o.Core
	if core == "" && len(o.RawOptions) > 0 {
		var written struct{ Core string }
		if err := decodeLegacy(o.RawOptions, &written); err == nil {
			core = written.Core
		}
	}
	switch {
	case core == "":
	case !slices.Contains(coreTypes, core):
		if lower := strings.ToLower(core); slices.Contains(coreTypes, lower) {
			v.add(path+".Core", "core must be lowercase %q", lower)
		} else {
			v.add(path+".Core", "unsupported core %q (use %s, or leave it empty)", core, quoteList(coreTypes))
		}
	case !coreTypeConfigured(cores, core):
		v.add(path+".Core", "no %q core is configured in Cores", core)
	}
	if o.CoreName == "" {
		return
	}
	coreType, ok := cores[o.CoreName]
	switch {
	case !ok:
		v.add(path+".CoreName", "no core named %q in Cores (a core's name is its Name, or its Type when Name is empty)", o.CoreName)
	case core != "" && coreType != core:
		v.add(path+".CoreName", "core %q is a %s core but Core is %q", o.CoreName, coreType, core)
	}
}

func coreTypeConfigured(cores map[string]string, coreType string) bool {
	for _, configured := range cores {
		if configured == coreType {
			return true
		}
	}
	return false
}

func (v *validator) checkOptions(path string, o *Options, cores map[string]string) {
	v.checkIP(path+".ListenIP", o.ListenIP)
	v.checkIP(path+".SendIP", o.SendIP)
	nonNegative(v, path+".DeviceOnlineMinTraffic", o.DeviceOnlineMinTraffic)
	nonNegative(v, path+".ReportMinTraffic", o.ReportMinTraffic)
	v.checkLimit(path+".LimitConfig", &o.LimitConfig)

	xray, sing := o.XrayOptions, o.SingOptions
	if o.Core == "" && len(o.RawOptions) > 0 {
		xray, sing = v.decodeUnpinnedOptions(path, o, cores)
	}
	if xray != nil {
		v.checkXrayOptions(path, xray)
	}
	if sing != nil {
		v.checkSingOptions(path, sing)
	}
	if artx := o.ArtXOptions; artx != nil {
		if artx.WindowBudgetSharePercent > maxArtXSharePercent {
			v.add(path+".ArtXOptions.WindowBudgetSharePercent", "must be between 0 and %d, got %d", maxArtXSharePercent, artx.WindowBudgetSharePercent)
		}
		if artx.WindowBudgetReservePercent > maxArtXReservePercent {
			v.add(path+".ArtXOptions.WindowBudgetReservePercent", "must be between 0 and %d, got %d", maxArtXReservePercent, artx.WindowBudgetReservePercent)
		}
	}
	v.checkCert(path+".CertConfig", o.CertConfig)
}

// decodeUnpinnedOptions reads options the way the core selector will: for a
// node without Core they are decoded once the serving core is known, which
// is the CoreName core or one of the configured cores. Only those readings
// can ever take effect, so only they are returned for checking.
func (v *validator) decodeUnpinnedOptions(path string, o *Options, cores map[string]string) (*XrayOptions, *SingOptions) {
	types := map[string]bool{}
	if coreType, ok := cores[o.CoreName]; ok && o.CoreName != "" {
		types[coreType] = true
	} else {
		for _, coreType := range cores {
			types[coreType] = true
		}
	}
	var (
		xray     *XrayOptions
		sing     *SingOptions
		firstErr error
	)
	if types["xray"] {
		xray = NewXrayOptions()
		if err := decodeLegacy(o.RawOptions, xray); err != nil {
			xray, firstErr = nil, err
		}
	}
	if types["sing"] {
		sing = NewSingOptions()
		if err := decodeLegacy(o.RawOptions, sing); err != nil {
			sing = nil
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil && xray == nil && sing == nil {
		v.add(path, "wrong value type: %v", firstErr)
	}
	return xray, sing
}

func (v *validator) checkLimit(path string, l *LimitConfig) {
	nonNegative(v, path+".SpeedLimit", l.SpeedLimit)
	nonNegative(v, path+".DeviceLimit", l.IPLimit)
	nonNegative(v, path+".ConnLimit", l.ConnLimit)
	dynamic := l.DynamicSpeedLimitConfig
	if dynamic == nil {
		if l.EnableDynamicSpeedLimit {
			v.add(path+".DynamicSpeedLimitConfig", "required when EnableDynamicSpeedLimit is true")
		}
		return
	}
	dynamicPath := path + ".DynamicSpeedLimitConfig"
	nonNegative(v, dynamicPath+".Periodic", dynamic.Periodic)
	nonNegative(v, dynamicPath+".Traffic", dynamic.Traffic)
	nonNegative(v, dynamicPath+".SpeedLimit", dynamic.SpeedLimit)
	nonNegative(v, dynamicPath+".ExpireTime", dynamic.ExpireTime)
}

func (v *validator) checkXrayOptions(path string, x *XrayOptions) {
	v.oneOf(path+".DNSType", "DNSType", x.DNSType, xrayDNSTypes)
	for i, fallback := range x.FallBackConfigs {
		fallbackPath := indexPath(path+".FallBackConfigs", i)
		if strings.TrimSpace(fallback.Dest) == "" {
			v.add(fallbackPath+".Dest", "required")
		}
		if fallback.ProxyProtocolVer > maxProxyProtocolVersion {
			v.add(fallbackPath+".ProxyProtocolVer", "must be 0, 1 or 2, got %d", fallback.ProxyProtocolVer)
		}
	}
}

func (v *validator) checkSingOptions(path string, s *SingOptions) {
	v.oneOf(path+".DomainStrategy", "DomainStrategy", s.DomainStrategy, singDomainStrategies)
	if fallback := s.FallBackConfigs; fallback != nil {
		v.checkPort(path+".FallBackConfigs.FallBack.ServerPort", fallback.FallBack.ServerPort)
		alpns := make([]string, 0, len(fallback.FallBackForALPN))
		for alpn := range fallback.FallBackForALPN {
			alpns = append(alpns, alpn)
		}
		slices.Sort(alpns)
		for _, alpn := range alpns {
			v.checkPort(path+".FallBackConfigs.FallBackForALPN."+alpn+".ServerPort", fallback.FallBackForALPN[alpn].ServerPort)
		}
	}
	if mux := s.Multiplex; mux != nil {
		nonNegative(v, path+".MultiplexConfig.Brutal.UpMbps", mux.Brutal.UpMbps)
		nonNegative(v, path+".MultiplexConfig.Brutal.DownMbps", mux.Brutal.DownMbps)
	}
	if shadowTLS := s.ShadowTLSOptions; shadowTLS != nil {
		if shadowTLS.Version < 0 || shadowTLS.Version > maxShadowTLSVersion {
			v.add(path+".ShadowTLSOptions.Version", "must be 1, 2 or 3 (0 keeps the panel's value), got %d", shadowTLS.Version)
		}
		v.oneOf(path+".ShadowTLSOptions.WildcardSNI", "WildcardSNI", shadowTLS.WildcardSNI, wildcardSNIModes)
	}
	if naive := s.NaiveOptions; naive != nil {
		v.oneOf(path+".NaiveOptions.Network", "network", naive.Network, naiveNetworks)
	}
	if hysteria := s.HysteriaOptions; hysteria != nil {
		v.checkPortHopping(path+".HysteriaOptions.PortHopping", hysteria.PortHopping)
		v.checkMasquerade(path+".HysteriaOptions.Masquerade", hysteria.Masquerade)
		nonNegative(v, path+".HysteriaOptions.MaxConnClient", hysteria.MaxConnClient)
	}
	if tuic := s.TuicOptions; tuic != nil {
		v.checkDuration(path+".TuicOptions.AuthTimeout", tuic.AuthTimeout)
		v.checkDuration(path+".TuicOptions.Heartbeat", tuic.Heartbeat)
		v.oneOf(path+".TuicOptions.CongestionControl", "congestion control", tuic.CongestionControl, tuicCongestion)
	}
}

func (v *validator) checkCert(path string, c *CertConfig) {
	if c == nil || c.CertMode == "" {
		return
	}
	if !slices.Contains(certModes, c.CertMode) {
		if lower := strings.ToLower(strings.TrimSpace(c.CertMode)); slices.Contains(certModes, lower) {
			v.add(path, "CertMode %q must be lowercase %q", c.CertMode, lower)
		} else {
			v.add(path, "unsupported CertMode %q (use %s)", c.CertMode, quoteList(certModes))
		}
		return
	}
	if c.CertMode == "none" {
		return
	}
	if strings.Contains(c.CertFile, "{domain}") || strings.Contains(c.KeyFile, "{domain}") {
		v.add(path, "CertFile or KeyFile uses {domain} but CertDomain is empty")
		return
	}
	switch c.CertMode {
	case "file", "self":
		if c.CertFile == "" || c.KeyFile == "" {
			v.add(path, "CertFile and KeyFile are required in %s mode", c.CertMode)
			return
		}
		if c.CertMode == "self" {
			return
		}
		for _, file := range []string{c.CertFile, c.KeyFile} {
			if info, err := os.Stat(file); err != nil || info.IsDir() {
				v.add(path, "certificate file not found: %s (file mode only reads existing files)", file)
			}
		}
	case "dns", "http":
		if err := ValidateACMECertConfig(c); err != nil {
			v.add(path, "%v", err)
		}
	}
}

type certFileUse struct {
	node   int
	domain string
}

// checkSharedCertFiles reports a certificate file that two nodes would write
// for different domains: each order would overwrite the other's certificate.
func (v *validator) checkSharedCertFiles(path string, node int, c *CertConfig, uses map[string]certFileUse) {
	if c == nil || !slices.Contains([]string{"dns", "http", "self"}, c.CertMode) {
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.CertDomain), "."))
	for _, file := range []struct{ key, path string }{{"CertFile", c.CertFile}, {"KeyFile", c.KeyFile}} {
		if file.path == "" {
			continue
		}
		clean := filepath.Clean(file.path)
		previous, used := uses[clean]
		switch {
		case !used:
			uses[clean] = certFileUse{node: node, domain: domain}
		case previous.domain != domain:
			v.add(path+"."+file.key, "%s is also used by Nodes[%d] for domain %q; each domain needs its own files", file.path, previous.node, previous.domain)
		}
	}
}
