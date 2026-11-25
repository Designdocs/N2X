package xray

import (
	"net"
	"strconv"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/core/xray/realitywebsite"
)

// The website is optional. Always build the original inbound first and never
// make its availability depend on website configuration, file I/O or probes.
func resolveRealityWebsite(o *conf.Options, node *panel.NodeInfo, network string) *realitywebsite.Config {
	if node.Type != "vless" || node.Security != panel.Reality || (network != "tcp" && network != "raw") {
		return nil
	}
	w := o.RealityWebsite
	if w == nil && node.Common.ServerPort != 443 || w != nil && w.Disabled {
		return nil
	}
	name := node.Common.Host
	if name == "" && o.DDNSConfig.Enabled {
		name = o.DDNSConfig.Domain
	}
	if name == "" && o.CertConfig != nil {
		name = o.CertConfig.CertDomain
	}
	var port int
	var proxy bool
	if w != nil {
		if w.ServerName != "" {
			name = w.ServerName
		}
		port, proxy = w.Port, w.ProxyProtocol
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if !conf.ValidWebsiteName(name) || strings.EqualFold(name, node.VAllss.TlsSettings.ServerName) {
		return nil
	}
	var addr string
	if port != 0 {
		if port < 1 || port > 65535 {
			return nil
		}
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	if port == node.Common.ServerPort {
		return nil
	}
	return &realitywebsite.Config{ServerName: name, Address: addr, ProxyProtocol: proxy}
}
