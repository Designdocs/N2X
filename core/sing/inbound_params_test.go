package sing

import (
	"testing"
	"time"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func tuicOptionsOf(t *testing.T, info *panel.NodeInfo, o *conf.Options) *option.TUICInboundOptions {
	t.Helper()
	in, err := getInboundOptions("tuic", info, o)
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts, ok := in.Options.(*option.TUICInboundOptions)
	if !ok {
		t.Fatalf("options type = %T", in.Options)
	}
	return opts
}

func TestTuicTimingsFromPanel(t *testing.T) {
	info := testNode("tuic", panel.Tls)
	info.Tuic = &panel.TuicNode{
		CongestionControl: "bbr",
		AuthTimeout:       panel.Duration(5 * time.Second),
		Heartbeat:         panel.Duration(12 * time.Second),
	}

	opts := tuicOptionsOf(t, info, testOptions())
	if time.Duration(opts.AuthTimeout) != 5*time.Second {
		t.Fatalf("auth timeout = %v", time.Duration(opts.AuthTimeout))
	}
	if time.Duration(opts.Heartbeat) != 12*time.Second {
		t.Fatalf("heartbeat = %v", time.Duration(opts.Heartbeat))
	}
}

func TestTuicTimingsFallBackToConfig(t *testing.T) {
	info := testNode("tuic", panel.Tls)
	info.Tuic = &panel.TuicNode{}
	options := testOptions()
	options.SingOptions.TuicOptions = &conf.TuicOptions{
		AuthTimeout:       "7s",
		Heartbeat:         "15s",
		CongestionControl: "bbr",
	}

	opts := tuicOptionsOf(t, info, options)
	if time.Duration(opts.AuthTimeout) != 7*time.Second || time.Duration(opts.Heartbeat) != 15*time.Second {
		t.Fatalf("timings = %v/%v", time.Duration(opts.AuthTimeout), time.Duration(opts.Heartbeat))
	}
	if opts.CongestionControl != "bbr" {
		t.Fatalf("congestion control = %q", opts.CongestionControl)
	}
}

// What the panel says wins: the local config only fills gaps.
func TestTuicPanelWinsOverConfig(t *testing.T) {
	info := testNode("tuic", panel.Tls)
	info.Tuic = &panel.TuicNode{CongestionControl: "cubic", Heartbeat: panel.Duration(3 * time.Second)}
	options := testOptions()
	options.SingOptions.TuicOptions = &conf.TuicOptions{Heartbeat: "30s", CongestionControl: "bbr"}

	opts := tuicOptionsOf(t, info, options)
	if time.Duration(opts.Heartbeat) != 3*time.Second {
		t.Fatalf("heartbeat = %v, want the panel's", time.Duration(opts.Heartbeat))
	}
	if opts.CongestionControl != "cubic" {
		t.Fatalf("congestion control = %q, want the panel's", opts.CongestionControl)
	}
}

func TestTuicRejectsUnparsableConfigDuration(t *testing.T) {
	info := testNode("tuic", panel.Tls)
	info.Tuic = &panel.TuicNode{}
	options := testOptions()
	options.SingOptions.TuicOptions = &conf.TuicOptions{Heartbeat: "soon"}

	if _, err := getInboundOptions("tuic", info, options); err == nil {
		t.Fatal("getInboundOptions returned no error for an unparsable heartbeat")
	}
}

func TestHysteriaQUICTuning(t *testing.T) {
	info := testNode("hysteria", panel.Tls)
	info.Hysteria = &panel.HysteriaNode{
		UpMbps:              100,
		DownMbps:            200,
		ReceiveWindowConn:   15728640,
		ReceiveWindowClient: 67108864,
		MaxConnClient:       1024,
		DisableMTUDiscovery: true,
	}

	in, err := getInboundOptions("hy1", info, testOptions())
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts := in.Options.(*option.HysteriaInboundOptions)
	if opts.ReceiveWindowConn != 15728640 || opts.ReceiveWindowClient != 67108864 {
		t.Fatalf("windows = %d/%d", opts.ReceiveWindowConn, opts.ReceiveWindowClient)
	}
	if opts.MaxConnClient != 1024 || !opts.DisableMTUDiscovery {
		t.Fatalf("conn options = %d/%v", opts.MaxConnClient, opts.DisableMTUDiscovery)
	}
}

func TestHysteriaQUICTuningFromConfig(t *testing.T) {
	info := testNode("hysteria", panel.Tls)
	info.Hysteria = &panel.HysteriaNode{}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{
		ReceiveWindowConn:   15728640,
		MaxConnClient:       512,
		DisableMTUDiscovery: true,
	}

	in, err := getInboundOptions("hy1", info, options)
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts := in.Options.(*option.HysteriaInboundOptions)
	if opts.ReceiveWindowConn != 15728640 || opts.MaxConnClient != 512 || !opts.DisableMTUDiscovery {
		t.Fatalf("options = %#v", opts)
	}
}

func hysteria2OptionsOf(t *testing.T, info *panel.NodeInfo, o *conf.Options) *option.Hysteria2InboundOptions {
	t.Helper()
	in, err := getInboundOptions("hy2", info, o)
	if err != nil {
		t.Fatalf("getInboundOptions: %v", err)
	}
	opts, ok := in.Options.(*option.Hysteria2InboundOptions)
	if !ok {
		t.Fatalf("options type = %T", in.Options)
	}
	return opts
}

// sing-box reads a masquerade URL straight out of a string, which is the form
// a panel is most likely to send.
func TestHysteria2MasqueradeURL(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{Masquerade: json.RawMessage(`"https://news.example.com"`)}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade == nil {
		t.Fatal("masquerade not set")
	}
	if opts.Masquerade.Type != C.Hysterai2MasqueradeTypeProxy {
		t.Fatalf("masquerade type = %q", opts.Masquerade.Type)
	}
	if opts.Masquerade.ProxyOptions.URL != "https://news.example.com" {
		t.Fatalf("masquerade url = %q", opts.Masquerade.ProxyOptions.URL)
	}
}

func TestHysteria2MasqueradeObject(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{
		Masquerade: json.RawMessage(`{"type":"string","status_code":404,"content":"not found"}`),
	}

	opts := hysteria2OptionsOf(t, info, testOptions())
	if opts.Masquerade == nil || opts.Masquerade.Type != C.Hysterai2MasqueradeTypeString {
		t.Fatalf("masquerade = %#v", opts.Masquerade)
	}
	if opts.Masquerade.StringOptions.StatusCode != 404 || opts.Masquerade.StringOptions.Content != "not found" {
		t.Fatalf("masquerade string options = %#v", opts.Masquerade.StringOptions)
	}
}

func TestHysteria2MasqueradeFromConfig(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{
		Masquerade:  "file:///var/www/html",
		BrutalDebug: true,
	}

	opts := hysteria2OptionsOf(t, info, options)
	if opts.Masquerade == nil || opts.Masquerade.Type != C.Hysterai2MasqueradeTypeFile {
		t.Fatalf("masquerade = %#v", opts.Masquerade)
	}
	if opts.Masquerade.FileOptions.Directory != "/var/www/html" {
		t.Fatalf("masquerade directory = %q", opts.Masquerade.FileOptions.Directory)
	}
	if !opts.BrutalDebug {
		t.Fatal("brutal debug not set")
	}
}

func TestHysteria2MasqueradeRejectsGarbage(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{Masquerade: json.RawMessage(`"ftp://example.com"`)}

	if _, err := getInboundOptions("hy2", info, testOptions()); err == nil {
		t.Fatal("getInboundOptions returned no error for an unusable masquerade")
	}
}

func TestHysteria2WithoutMasquerade(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{UpMbps: 100}

	if opts := hysteria2OptionsOf(t, info, testOptions()); opts.Masquerade != nil {
		t.Fatalf("masquerade = %#v, want none", opts.Masquerade)
	}
}
