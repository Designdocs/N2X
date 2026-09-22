package cdn

import "testing"

func TestProxyIPRanges(t *testing.T) {
	for _, prefix := range cloudflarePrefixes {
		if got := Provider(prefix.Addr().String()); got != Cloudflare {
			t.Errorf("cloudflare range start %s classified as %q", prefix, got)
		}
	}
	for _, prefix := range cloudfrontPrefixes {
		if got := Provider(prefix.Addr().String()); got != CloudFront {
			t.Errorf("cloudfront range start %s classified as %q", prefix, got)
		}
	}
	// The CloudFront addresses that were mistaken for devices on 2026-09-22.
	for _, ip := range []string{"15.158.212.208", "3.172.100.226", "::ffff:15.158.212.208"} {
		if got := Provider(ip); got != CloudFront {
			t.Errorf("%s classified as %q, want CloudFront", ip, got)
		}
	}
	// Plain EC2 space stays a countable device.
	for _, ip := range []string{"1.1.1.1", "203.0.113.1", "2001:db8::1", "172.63.255.255", "172.72.0.0", "56.69.64.164", "43.216.51.129", "cloudflare.com", "invalid", ""} {
		if IsProxyIP(ip) {
			t.Errorf("non-proxy accepted: %q", ip)
		}
	}
}
