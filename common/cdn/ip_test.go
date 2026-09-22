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

func TestGeneratedProviderRanges(t *testing.T) {
	for _, p := range generatedProviders {
		if len(p.prefixes) == 0 {
			t.Errorf("%s has no prefixes", p.name)
		}
		for _, prefix := range p.prefixes {
			if got := Provider(prefix.Addr().String()); got != p.name {
				t.Errorf("%s range start %s classified as %q", p.name, prefix, got)
			}
		}
	}
	samples := map[string]string{
		"151.101.1.1":            "Fastly",
		"2a04:4e42::1":           "Fastly",
		"23.32.0.1":              "Akamai",
		"2600:1400::1":           "Akamai",
		"35.191.0.1":             "Google Cloud",
		"130.211.3.255":          "Google Cloud",
		"34.96.0.1":              "Google Cloud",
		"4.153.250.1":            "Azure Front Door",
		"::ffff:151.101.1.1":     "Fastly",
		"2.78.47.38":             "Gcore",
		"2a03:90c0:11:2801::175": "Gcore",
		"89.187.188.227":         "Bunny",
		"2400:52e0:1500::714:1":  "Bunny",
	}
	for ip, want := range samples {
		if got := Provider(ip); got != want {
			t.Errorf("%s classified as %q, want %q", ip, got, want)
		}
	}
	// Neighbouring public space stays a countable device.
	for _, ip := range []string{"151.100.255.255", "23.31.255.255", "35.190.255.255", "34.95.255.255", "2a04:4e41::1"} {
		if IsProxyIP(ip) {
			t.Errorf("non-proxy accepted: %q", ip)
		}
	}
}
