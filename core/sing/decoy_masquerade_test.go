package sing

import (
	"encoding/json"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	C "github.com/sagernet/sing-box/constant"
)

// The selector is what an operator already writes for an xray fallback, so it
// has to mean the same thing here: proxy to the companion web service.
func TestHysteria2MasqueradeExpandsDecoySelector(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{Masquerade: json.RawMessage(`"` + decoy.Selector + `"`)}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade == nil || opts.Masquerade.Type != C.Hysterai2MasqueradeTypeProxy {
		t.Fatalf("masquerade = %#v", opts.Masquerade)
	}
	want := "http://" + decoy.DefaultListenAddress + "/"
	if opts.Masquerade.ProxyOptions.URL != want {
		t.Fatalf("masquerade url = %q, want %q", opts.Masquerade.ProxyOptions.URL, want)
	}
}

// The service moves with its configured listen address, which is the whole
// point of writing the selector instead of a port.
func TestHysteria2MasqueradeFollowsTheDecoyListenAddress(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "127.0.0.1:18080")

	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{Masquerade: json.RawMessage(`"` + decoy.Selector + `"`)}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade.ProxyOptions.URL != "http://127.0.0.1:18080/" {
		t.Fatalf("masquerade url = %q", opts.Masquerade.ProxyOptions.URL)
	}
}

// The node-local config is the fallback for panels that cannot send the field.
func TestHysteria2MasqueradeExpandsDecoySelectorFromConfig(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{Masquerade: " " + decoy.Selector + " "}

	opts := hysteria2OptionsOf(t, info, options)
	if opts.Masquerade == nil || opts.Masquerade.ProxyOptions.URL != "http://"+decoy.DefaultListenAddress+"/" {
		t.Fatalf("masquerade = %#v", opts.Masquerade)
	}
}

// The object form spells the same thing with an explicit url field.
func TestHysteria2MasqueradeExpandsDecoySelectorInObjectForm(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")

	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{
		Masquerade: json.RawMessage(`{"type":"proxy","url":"` + decoy.Selector + `","rewrite_host":true}`),
	}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade == nil || opts.Masquerade.ProxyOptions.URL != "http://"+decoy.DefaultListenAddress+"/" {
		t.Fatalf("masquerade = %#v", opts.Masquerade)
	}
	if !opts.Masquerade.ProxyOptions.RewriteHost {
		t.Fatal("rewrite_host was dropped while expanding the selector")
	}
}

// Only the selector is rewritten; a real URL reaches sing-box as written.
func TestHysteria2MasqueradeLeavesOtherURLsAlone(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{Masquerade: json.RawMessage(`"http://127.0.0.1:60443"`)}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade.ProxyOptions.URL != "http://127.0.0.1:60443" {
		t.Fatalf("masquerade url = %q", opts.Masquerade.ProxyOptions.URL)
	}
}
