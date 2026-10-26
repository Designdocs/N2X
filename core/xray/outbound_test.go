package xray

import (
	"testing"

	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestOutboundDNSStrategyUsesSockopt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		dns     string
		want    internet.DomainStrategy
	}{
		{"DNS disabled", false, "UseIPv6", internet.DomainStrategy_AS_IS},
		{"default resolution", true, "", internet.DomainStrategy_USE_IP},
		{"IPv4", true, "UseIPv4", internet.DomainStrategy_USE_IP4},
		{"IPv6", true, "UseIPv6", internet.DomainStrategy_USE_IP6},
		{"forced IPv6", true, "ForceIPv6", internet.DomainStrategy_FORCE_IP6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := &conf.Options{SendIP: "192.0.2.1", XrayOptions: conf.NewXrayOptions()}
			options.XrayOptions.EnableDNS = tc.enabled
			options.XrayOptions.DNSType = tc.dns
			out, err := buildOutbound(options, "node-direct")
			if err != nil {
				t.Fatal(err)
			}
			senderMessage, err := out.SenderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			sender := senderMessage.(*proxyman.SenderConfig)
			if got := sender.StreamSettings.SocketSettings.DomainStrategy; got != tc.want {
				t.Fatalf("socket DNS strategy = %v, want %v", got, tc.want)
			}
			if out.Tag != "node-direct" || sender.Via.AsAddress().String() != "192.0.2.1" {
				t.Fatal("outbound tag or send address changed")
			}
			proxy, err := out.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if proxy.(*freedom.Config).DomainStrategy != internet.DomainStrategy_AS_IS {
				t.Fatal("deprecated freedom strategy is still emitted")
			}
		})
	}
	options := &conf.Options{XrayOptions: conf.NewXrayOptions()}
	options.XrayOptions.EnableDNS = true
	options.XrayOptions.DNSType = "invalid-strategy"
	if _, err := buildOutbound(options, "invalid"); err == nil {
		t.Fatal("invalid DNS strategy accepted")
	}
}
