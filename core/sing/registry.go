package sing

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	protocolDNS "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	E "github.com/sagernet/sing/common/exceptions"
)

// The registries below deliberately replace sing-box's own include package.
//
// N2X is a server-side agent: it terminates proxy protocols for panel users
// and forwards their traffic out. It never needs the client-oriented and
// host-integration pieces sing-box also ships — TUN, redirect/TProxy, SOCKS,
// HTTP, mixed, Tor, SSH, WireGuard, Tailscale and the management services.
// Leaving them out keeps the binary smaller and, more importantly, keeps this
// core off the parts of sing-box_mod that no longer compile against the
// github.com/sagernet/sing version xray-core requires. See docs/sing-box.md
// for the dependency analysis behind that pin.

func inboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	// Needed as a detour/chain target, not as a public listener.
	direct.RegisterInbound(registry)

	shadowsocks.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)

	registerQUICInbounds(registry)
	registerRemovedInboundStubs(registry)

	return registry
}

func outboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	// direct is how user traffic actually leaves the node; block and dns back
	// the routing rules the panel pushes down.
	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)
	protocolDNS.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	return registry
}

func endpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

func dnsTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)

	registerQUICTransports(registry)

	return registry
}

func serviceRegistry() *service.Registry {
	return service.NewRegistry()
}

// registerRemovedInboundStubs keeps a config referencing a long-removed
// protocol failing with a clear message instead of "unknown inbound type".
func registerRemovedInboundStubs(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR,
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
			return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
		})
}
