package cloudflare

import "testing"

func TestProxyIPRanges(t *testing.T) {
	for _, prefix := range prefixes {
		if !IsProxyIP(prefix.Addr().String()) {
			t.Errorf("range start not recognized: %s", prefix)
		}
	}
	for _, ip := range []string{"1.1.1.1", "203.0.113.1", "2001:db8::1", "172.63.255.255", "172.72.0.0", "cloudflare.com", "invalid", ""} {
		if IsProxyIP(ip) {
			t.Errorf("non-proxy accepted: %q", ip)
		}
	}
}
