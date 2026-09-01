package sing

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/option"
)

func shadowTLSOptionsOf(t *testing.T, info *panel.NodeInfo, o *conf.Options) *option.ShadowTLSInboundOptions {
	t.Helper()
	inbounds, err := buildShadowTLSInbounds("stls", info, o)
	if err != nil {
		t.Fatalf("buildShadowTLSInbounds: %v", err)
	}
	// The public listener is built after the detour it hands streams to.
	opts, ok := inbounds[len(inbounds)-1].Options.(*option.ShadowTLSInboundOptions)
	if !ok {
		t.Fatalf("options type = %T", inbounds[len(inbounds)-1].Options)
	}
	return opts
}

func shadowTLSNode() *panel.NodeInfo {
	info := testNode("shadowtls", panel.None)
	info.ShadowTLS = &panel.ShadowTLSNode{
		Version:   3,
		Password:  "s3cret",
		Cipher:    "2022-blake3-aes-128-gcm",
		ServerKey: "kEyBase64",
		Handshake: panel.ShadowTLSHandshake{Server: "www.example.com", ServerPort: 443},
	}
	return info
}

// A per-SNI handshake target lets one listener camouflage as several sites.
func TestShadowTLSHandshakeForServerNameFromPanel(t *testing.T) {
	info := shadowTLSNode()
	info.ShadowTLS.HandshakeForServerName = map[string]panel.ShadowTLSHandshake{
		"www.apple.com":     {Server: "www.apple.com", ServerPort: 443},
		"www.microsoft.com": {Server: "www.microsoft.com"},
	}

	opts := shadowTLSOptionsOf(t, info, testOptions())
	if opts.HandshakeForServerName == nil {
		t.Fatal("handshake_for_server_name not set")
	}
	apple, ok := opts.HandshakeForServerName.Get("www.apple.com")
	if !ok || apple.Server != "www.apple.com" || apple.ServerPort != 443 {
		t.Fatalf("apple handshake = %#v (found %v)", apple, ok)
	}
	// A target with no port falls back to 443 like the primary handshake does.
	microsoft, ok := opts.HandshakeForServerName.Get("www.microsoft.com")
	if !ok || microsoft.ServerPort != 443 {
		t.Fatalf("microsoft handshake = %#v (found %v)", microsoft, ok)
	}
}

func TestShadowTLSHandshakeForServerNameFromConfig(t *testing.T) {
	info := shadowTLSNode()
	options := testOptions()
	options.SingOptions.ShadowTLSOptions = &conf.ShadowTLSOptions{
		HandshakeForServerName: map[string]conf.ShadowTLSHandshakeTarget{
			"www.apple.com": {Server: "www.apple.com", ServerPort: 8443},
		},
	}

	opts := shadowTLSOptionsOf(t, info, options)
	apple, ok := opts.HandshakeForServerName.Get("www.apple.com")
	if !ok || apple.ServerPort != 8443 {
		t.Fatalf("apple handshake = %#v (found %v)", apple, ok)
	}
}

// The local config overrides the panel entry for the same SNI and leaves the
// rest of the panel's map alone.
func TestShadowTLSHandshakeForServerNameConfigOverridesPanel(t *testing.T) {
	info := shadowTLSNode()
	info.ShadowTLS.HandshakeForServerName = map[string]panel.ShadowTLSHandshake{
		"www.apple.com": {Server: "www.apple.com", ServerPort: 443},
		"www.bing.com":  {Server: "www.bing.com", ServerPort: 443},
	}
	options := testOptions()
	options.SingOptions.ShadowTLSOptions = &conf.ShadowTLSOptions{
		HandshakeForServerName: map[string]conf.ShadowTLSHandshakeTarget{
			"www.apple.com": {Server: "cdn.example.com", ServerPort: 8443},
		},
	}

	opts := shadowTLSOptionsOf(t, info, options)
	apple, _ := opts.HandshakeForServerName.Get("www.apple.com")
	if apple.Server != "cdn.example.com" || apple.ServerPort != 8443 {
		t.Fatalf("apple handshake = %#v, want the config override", apple)
	}
	if bing, ok := opts.HandshakeForServerName.Get("www.bing.com"); !ok || bing.Server != "www.bing.com" {
		t.Fatalf("bing handshake = %#v (found %v)", bing, ok)
	}
}

func TestShadowTLSWithoutPerSNIHandshake(t *testing.T) {
	if opts := shadowTLSOptionsOf(t, shadowTLSNode(), testOptions()); opts.HandshakeForServerName != nil {
		t.Fatal("handshake_for_server_name set although nothing configured one")
	}
}
