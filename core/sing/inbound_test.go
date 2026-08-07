package sing

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func testOptions() *conf.Options {
	o := &conf.Options{
		ListenIP: "0.0.0.0",
		CertConfig: &conf.CertConfig{
			CertMode: "file",
			CertFile: "/etc/N2X/fullchain.cer",
			KeyFile:  "/etc/N2X/cert.key",
		},
	}
	o.SingOptions = conf.NewSingOptions()
	return o
}

func testNode(nodeType string, security int) *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:     nodeType,
		Security: security,
		Common:   &panel.CommonNode{ServerPort: 8443, Host: "node.example.com"},
	}
}

func TestGetInboundOptionsHysteria2(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{
		UpMbps:                100,
		DownMbps:              200,
		ObfsType:              "salamander",
		ObfsPassword:          "s3cret",
		IgnoreClientBandwidth: true,
	}

	in, err := getInboundOptions("hy2", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	if in.Type != "hysteria2" || in.Tag != "hy2" {
		t.Fatalf("type/tag = %q/%q", in.Type, in.Tag)
	}
	opts, ok := in.Options.(*option.Hysteria2InboundOptions)
	if !ok {
		t.Fatalf("options type = %T", in.Options)
	}
	if opts.UpMbps != 100 || opts.DownMbps != 200 || !opts.IgnoreClientBandwidth {
		t.Fatalf("bandwidth options = %#v", opts)
	}
	if opts.Obfs == nil || opts.Obfs.Type != "salamander" || opts.Obfs.Password != "s3cret" {
		t.Fatalf("obfs = %#v", opts.Obfs)
	}
	if opts.ListenPort != 8443 {
		t.Fatalf("listen port = %d", opts.ListenPort)
	}
	if opts.TLS == nil || !opts.TLS.Enabled {
		t.Fatal("TLS should be enabled for hysteria2")
	}
}

// A panel that only sends "obfs" means the value is the Salamander password,
// not the obfuscation type.
func TestBuildHysteria2ObfsPasswordOnly(t *testing.T) {
	obfs := buildHysteria2Obfs(&panel.Hysteria2Node{ObfsType: "justapassword"})
	if obfs == nil || obfs.Type != "salamander" || obfs.Password != "justapassword" {
		t.Fatalf("obfs = %#v", obfs)
	}
	if buildHysteria2Obfs(&panel.Hysteria2Node{}) != nil {
		t.Fatal("no obfs settings should produce no obfs block")
	}
}

func TestGetInboundOptionsTuicAdvertisesH3(t *testing.T) {
	info := testNode("tuic", panel.Tls)
	info.Tuic = &panel.TuicNode{CongestionControl: "bbr", ZeroRTTHandshake: true}

	in, err := getInboundOptions("tuic", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts := in.Options.(*option.TUICInboundOptions)
	if opts.CongestionControl != "bbr" || !opts.ZeroRTTHandshake {
		t.Fatalf("tuic options = %#v", opts)
	}
	// TUIC runs on QUIC: without h3 in the ALPN list clients cannot connect.
	if opts.TLS == nil || len(opts.TLS.ALPN) == 0 || opts.TLS.ALPN[0] != "h3" {
		t.Fatalf("ALPN = %#v", opts.TLS)
	}
}

func TestGetInboundOptionsAnyTLS(t *testing.T) {
	info := testNode("anytls", panel.Tls)
	info.AnyTls = &panel.AnyTlsNode{PaddingScheme: []string{"stop=8"}}

	in, err := getInboundOptions("anytls", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	if in.Type != "anytls" {
		t.Fatalf("type = %q", in.Type)
	}
	opts := in.Options.(*option.AnyTLSInboundOptions)
	if len(opts.PaddingScheme) != 1 || opts.PaddingScheme[0] != "stop=8" {
		t.Fatalf("padding scheme = %#v", opts.PaddingScheme)
	}
}

func TestGetInboundOptionsRejectsMissingSettings(t *testing.T) {
	for _, nodeType := range []string{"hysteria2", "tuic", "anytls", "vless", "trojan", "shadowsocks"} {
		if _, err := getInboundOptions("t", testNode(nodeType, panel.Tls), testOptions()); err == nil {
			t.Fatalf("%s: expected an error when node settings are absent", nodeType)
		}
	}
	if _, err := getInboundOptions("t", testNode("nonsense", panel.Tls), testOptions()); err == nil {
		t.Fatal("expected an error for an unknown node type")
	}
}

func TestBuildShadowTLSInboundsChainsToDetour(t *testing.T) {
	info := testNode("shadowtls", panel.None)
	info.ShadowTLS = &panel.ShadowTLSNode{
		Version:   3,
		Password:  "node-password",
		Handshake: panel.ShadowTLSHandshake{Server: "www.microsoft.com", ServerPort: 443},
		Cipher:    "2022-blake3-aes-128-gcm",
		ServerKey: "c2VydmVya2V5",
	}

	inbounds, err := buildShadowTLSInbounds("stls", info, testOptions())
	if err != nil {
		t.Fatalf("buildShadowTLSInbounds: %v", err)
	}
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(inbounds))
	}
	// The detour must come first so the chain target exists before the public
	// listener starts accepting.
	detour, public := inbounds[0], inbounds[1]
	if detour.Type != "shadowsocks" || detour.Tag != "stls$detour" {
		t.Fatalf("detour = %q/%q", detour.Type, detour.Tag)
	}
	if public.Type != "shadowtls" || public.Tag != "stls" {
		t.Fatalf("public = %q/%q", public.Type, public.Tag)
	}

	publicOpts := public.Options.(*option.ShadowTLSInboundOptions)
	if publicOpts.ListenOptions.InboundOptions.Detour != "stls$detour" {
		t.Fatalf("detour link = %q", publicOpts.ListenOptions.InboundOptions.Detour)
	}
	if publicOpts.ListenPort != 8443 {
		t.Fatalf("public listen port = %d", publicOpts.ListenPort)
	}
	if publicOpts.Version != 3 {
		t.Fatalf("version = %d", publicOpts.Version)
	}
	// v3 authenticates from the user list, not the shared password field.
	if len(publicOpts.Users) != 1 || publicOpts.Users[0].Password != "node-password" {
		t.Fatalf("v3 users = %#v", publicOpts.Users)
	}
	if publicOpts.Password != "" {
		t.Fatalf("v3 must not set the v2 shared password, got %q", publicOpts.Password)
	}
	if publicOpts.Handshake.Server != "www.microsoft.com" || publicOpts.Handshake.ServerPort != 443 {
		t.Fatalf("handshake = %#v", publicOpts.Handshake)
	}

	detourOpts := detour.Options.(*option.ShadowsocksInboundOptions)
	if detourOpts.Method != "2022-blake3-aes-128-gcm" {
		t.Fatalf("detour method = %q", detourOpts.Method)
	}
	// The detour is internal and must never be reachable from off-host.
	if detourOpts.Listen == nil || detourOpts.Listen.Build(netip.IPv6Unspecified()).String() != "127.0.0.1" {
		t.Fatalf("detour listen address = %v", detourOpts.Listen)
	}
	if detourOpts.ListenPort != 0 {
		t.Fatalf("detour should take an ephemeral port, got %d", detourOpts.ListenPort)
	}
}

func TestBuildShadowTLSVersion2UsesSharedPassword(t *testing.T) {
	info := testNode("shadowtls", panel.None)
	info.ShadowTLS = &panel.ShadowTLSNode{
		Version:   2,
		Password:  "shared",
		Handshake: panel.ShadowTLSHandshake{Server: "example.org", ServerPort: 443},
		Cipher:    "aes-128-gcm",
	}
	inbounds, err := buildShadowTLSInbounds("stls", info, testOptions())
	if err != nil {
		t.Fatalf("buildShadowTLSInbounds: %v", err)
	}
	opts := inbounds[1].Options.(*option.ShadowTLSInboundOptions)
	if opts.Password != "shared" || len(opts.Users) != 0 {
		t.Fatalf("v2 auth = password %q users %#v", opts.Password, opts.Users)
	}
}

func TestBuildShadowTLSLocalOverrides(t *testing.T) {
	info := testNode("shadowtls", panel.None)
	info.ShadowTLS = &panel.ShadowTLSNode{
		Version:   3,
		Password:  "p",
		Handshake: panel.ShadowTLSHandshake{Server: "panel.example.com", ServerPort: 443},
		Cipher:    "2022-blake3-aes-128-gcm",
	}
	options := testOptions()
	options.SingOptions.ShadowTLSOptions = &conf.ShadowTLSOptions{
		HandshakeServer:     "local.example.net",
		HandshakeServerPort: 8443,
		StrictMode:          true,
		WildcardSNI:         "authed",
	}

	inbounds, err := buildShadowTLSInbounds("stls", info, options)
	if err != nil {
		t.Fatalf("buildShadowTLSInbounds: %v", err)
	}
	opts := inbounds[1].Options.(*option.ShadowTLSInboundOptions)
	if opts.Handshake.Server != "local.example.net" || opts.Handshake.ServerPort != 8443 {
		t.Fatalf("overrides not applied: %#v", opts.Handshake)
	}
	if !opts.StrictMode || opts.WildcardSNI != option.ShadowTLSWildcardSNIAuthed {
		t.Fatalf("strict/wildcard = %v/%v", opts.StrictMode, opts.WildcardSNI)
	}
}

func TestBuildShadowTLSRequiresHandshakeServer(t *testing.T) {
	info := testNode("shadowtls", panel.None)
	info.ShadowTLS = &panel.ShadowTLSNode{Version: 3, Cipher: "aes-128-gcm"}
	if _, err := buildShadowTLSInbounds("stls", info, testOptions()); err == nil {
		t.Fatal("a ShadowTLS node without a handshake target should be rejected")
	}
}

func TestBuildNaiveOptionsRequiresTLS(t *testing.T) {
	info := testNode("naive", panel.Tls)
	info.Naive = &panel.NaiveNode{}
	options := testOptions()
	options.CertConfig.CertMode = "none"

	if _, err := buildNaiveOptions(info, options, nil); err == nil {
		t.Fatal("naive without TLS should be rejected")
	}
}

func TestBuildNaiveOptionsSetsHTTPALPN(t *testing.T) {
	info := testNode("naive", panel.Tls)
	info.Naive = &panel.NaiveNode{Network: "tcp"}

	opts, err := buildNaiveOptions(info, testOptions(), nil)
	if err != nil {
		t.Fatalf("buildNaiveOptions: %v", err)
	}
	if opts.Network != option.NetworkList("tcp") {
		t.Fatalf("network = %q", opts.Network)
	}
	alpn := strings.Join(opts.TLS.ALPN, ",")
	if !strings.Contains(alpn, "h2") || !strings.Contains(alpn, "http/1.1") {
		t.Fatalf("ALPN = %q, naive needs h2 and http/1.1", alpn)
	}
}

func TestBuildShadowsocksUsersDerivesKeys(t *testing.T) {
	users := []panel.UserInfo{{Id: 1, Uuid: "0123456789abcdef0123456789abcdef1234"}}

	// Non-2022 ciphers take the passphrase unchanged.
	plain := buildShadowsocksUsers(users, "aes-128-gcm")
	if plain[0].Password != users[0].Uuid {
		t.Fatalf("legacy cipher password = %q", plain[0].Password)
	}

	for cipher, wantLen := range map[string]int{
		"2022-blake3-aes-128-gcm":       16,
		"2022-blake3-aes-256-gcm":       32,
		"2022-blake3-chacha20-poly1305": 32,
	} {
		got := buildShadowsocksUsers(users, cipher)
		raw, err := base64.StdEncoding.DecodeString(got[0].Password)
		if err != nil {
			t.Fatalf("%s: password is not base64: %v", cipher, err)
		}
		if len(raw) != wantLen {
			t.Fatalf("%s: key length = %d, want %d", cipher, len(raw), wantLen)
		}
		if got[0].Name != users[0].Uuid {
			t.Fatalf("%s: user name = %q", cipher, got[0].Name)
		}
	}
}

// A UUID shorter than the cipher's key size must not panic on the slice.
func TestBuildShadowsocksUsersShortPassword(t *testing.T) {
	got := buildShadowsocksUsers([]panel.UserInfo{{Uuid: "short"}}, "2022-blake3-aes-256-gcm")
	if got[0].Password == "" {
		t.Fatal("short password should still produce a key")
	}
}

func TestParseDomainStrategy(t *testing.T) {
	for in, want := range map[string]option.DomainStrategy{
		"prefer_ipv4": option.DomainStrategy(C.DomainStrategyPreferIPv4),
		"prefer_ipv6": option.DomainStrategy(C.DomainStrategyPreferIPv6),
		"ipv4_only":   option.DomainStrategy(C.DomainStrategyIPv4Only),
		"ipv6_only":   option.DomainStrategy(C.DomainStrategyIPv6Only),
		"":            option.DomainStrategy(C.DomainStrategyAsIS),
		"garbage":     option.DomainStrategy(C.DomainStrategyAsIS),
	} {
		if got := parseDomainStrategy(in); got != want {
			t.Fatalf("parseDomainStrategy(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseWildcardSNI(t *testing.T) {
	for in, want := range map[string]option.WildcardSNI{
		"authed":  option.ShadowTLSWildcardSNIAuthed,
		"all":     option.ShadowTLSWildcardSNIAll,
		"off":     option.ShadowTLSWildcardSNIOff,
		"":        option.ShadowTLSWildcardSNIOff,
		"garbage": option.ShadowTLSWildcardSNIOff,
	} {
		if got := parseWildcardSNI(in); got != want {
			t.Fatalf("parseWildcardSNI(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUserInboundTagRoutesShadowTLSToDetour(t *testing.T) {
	if got := userInboundTag("node", "shadowtls"); got != "node$detour" {
		t.Fatalf("shadowtls user inbound = %q", got)
	}
	for _, nodeType := range []string{"anytls", "hysteria2", "tuic", "vless"} {
		if got := userInboundTag("node", nodeType); got != "node" {
			t.Fatalf("%s user inbound = %q", nodeType, got)
		}
	}
}

func TestEnsureSingOptionsDecodesRawOptions(t *testing.T) {
	options := &conf.Options{
		RawOptions: []byte(`{"EnableTFO":true,"DomainStrategy":"prefer_ipv4"}`),
	}
	if err := ensureSingOptions(options); err != nil {
		t.Fatalf("ensureSingOptions: %v", err)
	}
	if options.SingOptions == nil || !options.SingOptions.TCPFastOpen {
		t.Fatalf("sing options = %#v", options.SingOptions)
	}
	if options.SingOptions.DomainStrategy != "prefer_ipv4" {
		t.Fatalf("domain strategy = %q", options.SingOptions.DomainStrategy)
	}

	// Already-decoded options must be left alone.
	existing := conf.NewSingOptions()
	existing.TCPFastOpen = true
	preset := &conf.Options{SingOptions: existing}
	if err := ensureSingOptions(preset); err != nil {
		t.Fatalf("ensureSingOptions: %v", err)
	}
	if preset.SingOptions != existing {
		t.Fatal("existing sing options were replaced")
	}
}
