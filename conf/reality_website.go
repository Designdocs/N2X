package conf

import (
	"net/netip"

	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

// RealityWebsite forwards a single SNI to an HTTPS listener on IPv4 loopback.
type RealityWebsite struct {
	ServerName    string
	Port          int
	ProxyProtocol bool
	Disabled      bool
}

func ValidWebsiteName(name string) bool {
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	return M.IsDomainName(name) && !strings.ContainsAny(name, "_*") && !strings.HasSuffix(name, ".")
}
