package conf

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Designdocs/N2X/common/porthop"
	"github.com/Designdocs/N2X/decoy"
)

var (
	logLevels      = []string{"debug", "info", "warn", "error"}
	coreTypes      = []string{"xray", "sing"}
	xrayLogLevels  = []string{"debug", "info", "warning", "error", "none"}
	singLogLevels  = []string{"trace", "debug", "info", "warn", "warning", "error", "fatal", "panic"}
	panelNodeTypes = []string{
		"v2ray", "anytls", "artx", "vmess", "trojan", "shadowsocks", "vless",
		"hysteria", "hysteria2", "tuic", "shadowtls", "naive",
	}
	xrayDNSTypes = []string{
		"asis", "useip", "useipv4", "useipv6", "useipv4v6", "useipv6v4",
		"forceip", "forceipv4", "forceipv6", "forceipv4v6", "forceipv6v4",
	}
	singDomainStrategies = []string{"as_is", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}
	wildcardSNIModes     = []string{"off", "authed", "all"}
	naiveNetworks        = []string{"tcp", "udp"}
	tuicCongestion       = []string{"cubic", "new_reno", "bbr"}
	masqueradeSchemes    = []string{"http", "https", "file"}
	certModes            = []string{"none", "file", "self", "http", "dns"}
)

const (
	maxProxyProtocolVersion = 2
	maxShadowTLSVersion     = 3
	maxArtXSharePercent     = 100
	maxArtXReservePercent   = 99
	maxPort                 = 65535
)

func (v *validator) checkConf(c *Conf) {
	v.checkLog(c.LogConfig)
	names := v.checkCores(c.CoresConfig)
	v.checkNodes(c.NodeConfig, names)
}

func (v *validator) checkLog(l LogConfig) {
	if l.Level != "" && !slices.Contains(logLevels, l.Level) {
		v.add("Log.Level", "unsupported level %q (use %s)", l.Level, quoteList(logLevels))
	}
	v.checkParentDir("Log.Output", l.Output)
}

// checkCores returns the type of each core by the name nodes refer to it by.
func (v *validator) checkCores(cores []CoreConfig) map[string]string {
	names := map[string]string{}
	if len(cores) == 0 {
		v.add("Cores", "at least one core is required")
		return names
	}
	seen := map[string]int{}
	for i, core := range cores {
		path := indexPath("Cores", i)
		v.checkCoreType(path+".Type", core.Type)
		name := core.Name
		if name == "" {
			name = core.Type
		}
		if first, dup := seen[name]; dup {
			v.add(path, "duplicate core name %q (same as Cores[%d]); give each core a distinct Name", name, first)
		} else {
			seen[name] = i
			names[name] = core.Type
		}
		switch {
		case core.XrayConfig != nil:
			v.checkXrayCore(path, core.XrayConfig)
		case core.SingConfig != nil:
			v.checkSingCore(path, core.SingConfig)
		}
	}
	return names
}

func (v *validator) checkCoreType(path, coreType string) {
	if !slices.Contains(coreTypes, coreType) {
		if lower := strings.ToLower(coreType); slices.Contains(coreTypes, lower) {
			v.add(path, "core type must be lowercase %q", lower)
			return
		}
		v.add(path, "unsupported core type %q (use %s)", coreType, quoteList(coreTypes))
		return
	}
	if len(v.opts.CoreTypes) > 0 && !slices.Contains(v.opts.CoreTypes, coreType) {
		v.add(path, "core type %q is not built into this binary (available: %s)", coreType, quoteList(v.opts.CoreTypes))
	}
}

func (v *validator) checkXrayCore(path string, x *XrayConfig) {
	if x.LogConfig != nil {
		if level := x.LogConfig.Level; level != "" && !slices.Contains(xrayLogLevels, strings.ToLower(level)) {
			v.add(path+".Log.Level", "unsupported xray log level %q (use %s)", level, quoteList(xrayLogLevels))
		}
		for _, logFile := range []struct{ key, path string }{
			{"AccessPath", x.LogConfig.AccessPath},
			{"ErrorPath", x.LogConfig.ErrorPath},
		} {
			if logFile.path != "none" {
				v.checkParentDir(path+".Log."+logFile.key, logFile.path)
			}
		}
	}
	// xray logs a bad DNS file and runs with its default DNS settings, so this
	// one does not stop the config. A running xray already has DNS settings
	// though, and a reload would drop them.
	v.asWarnings("ignored: xray runs with its default DNS settings",
		"reload rejected: xray keeps its current DNS settings", func() {
			v.checkJSONFile(path+".DnsConfigPath", x.DnsConfigPath, false)
		})
	v.checkJSONFile(path+".RouteConfigPath", x.RouteConfigPath, false)
	v.checkJSONFile(path+".InboundConfigPath", x.InboundConfigPath, true)
	v.checkJSONFile(path+".OutboundConfigPath", x.OutboundConfigPath, true)
}

func (v *validator) checkSingCore(path string, s *SingConfig) {
	if level := s.LogConfig.Level; level != "" && !slices.Contains(singLogLevels, level) {
		v.add(path+".Log.Level", "unsupported sing-box log level %q (use %s)", level, quoteList(singLogLevels))
	}
	v.checkParentDir(path+".Log.Output", s.LogConfig.Output)
	if s.NtpConfig.Enable && strings.TrimSpace(s.NtpConfig.Server) == "" {
		v.add(path+".NTP.Server", "required when NTP is enabled")
	}
	if s.OriginalPath != "" {
		if _, err := os.ReadFile(s.OriginalPath); err != nil {
			v.add(path+".OriginalPath", "cannot read %s: %v", s.OriginalPath, err)
		}
	}
}

// checkJSONFile parses a file xray reads itself with strict JSON. A bad
// route, inbound or outbound file aborts the whole process; a bad DNS file is
// only logged and xray runs without the DNS settings.
func (v *validator) checkJSONFile(path, file string, wantArray bool) {
	if file == "" {
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		v.add(path, "cannot read %s: %v", file, err)
		return
	}
	var tree any
	if err := jsonv2.Unmarshal(raw, &tree); err != nil {
		before := len(v.issues)
		v.addSyntaxError("", raw, err)
		for i := before; i < len(v.issues); i++ {
			v.issues[i] = Issue{Path: path, Message: fmt.Sprintf("%s: %s", file, v.issues[i].String()), Kind: v.issues[i].Kind}
		}
		return
	}
	switch _, isArray := tree.([]any); {
	case wantArray && !isArray:
		v.add(path, "%s must contain a JSON array", file)
	case !wantArray:
		if _, isObject := tree.(map[string]any); !isObject {
			v.add(path, "%s must contain a JSON object", file)
		}
	}
}

func (v *validator) checkParentDir(path, file string) {
	if file == "" {
		return
	}
	dir := filepath.Dir(file)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		v.add(path, "directory %s does not exist", dir)
	}
}

func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = strconv.Quote(value)
	}
	return strings.Join(quoted, ", ")
}

func nonNegative[T int | int64](v *validator, path string, value T) {
	if value < 0 {
		v.add(path, "must not be negative, got %d", value)
	}
}

// oneOf reports value unless it is empty or, compared in lower case, one of
// allowed.
func (v *validator) oneOf(path, what, value string, allowed []string) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized != "" && !slices.Contains(allowed, normalized) {
		v.add(path, "unsupported %s %q (use %s)", what, value, quoteList(allowed))
	}
}

func (v *validator) checkURL(path, value string, schemes []string) {
	parsed, err := url.Parse(value)
	if err != nil || !slices.Contains(schemes, parsed.Scheme) || parsed.Host == "" {
		prefixes := make([]string, len(schemes))
		for i, scheme := range schemes {
			prefixes[i] = scheme + "://"
		}
		v.add(path, "must be a %s URL with a host, got %q", strings.Join(prefixes, " or "), value)
	}
}

func (v *validator) checkIP(path, value string) {
	if value == "" {
		return
	}
	if _, err := netip.ParseAddr(value); err != nil {
		v.add(path, "%q is not a valid IP address (no port or brackets)", value)
	}
}

func (v *validator) checkDuration(path, value string) {
	if value == "" {
		return
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		v.add(path, "%q is not a duration like \"10s\" or \"1m\"", value)
		return
	}
	if duration < 0 {
		v.add(path, "must not be negative, got %s", value)
	}
}

func (v *validator) checkPort(path, value string) {
	if value == "" {
		return
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > maxPort {
		v.add(path, "%q is not a port between 1 and %d", value, maxPort)
	}
}

func (v *validator) checkMasquerade(path, value string) {
	value = strings.TrimSpace(value)
	if value == "" || value == decoy.Selector {
		return
	}
	parsed, err := url.Parse(value)
	if err != nil || !slices.Contains(masqueradeSchemes, parsed.Scheme) {
		scheme := value
		if err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		v.add(path, "unsupported masquerade %q (use an http://, https:// or file:// URL, or %s)", scheme, decoy.Selector)
		return
	}
	if parsed.Scheme != "file" && parsed.Host == "" {
		v.add(path, "masquerade URL %q has no host", value)
	}
}

func (v *validator) checkPortHopping(path string, ranges []string) {
	if len(ranges) == 0 {
		return
	}
	if _, err := porthop.ParseRanges(ranges); err != nil {
		v.add(path, "%v", err)
	}
}
