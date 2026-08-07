package sing

import (
	"fmt"
	"net/netip"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// buildShadowTLSInbounds expands a ShadowTLS node into the two inbounds that
// serve it.
//
// The public listener speaks ShadowTLS: it relays a genuine TLS handshake to
// an upstream site so that an active prober sees only that site's
// certificate, then hands authenticated streams to the detour. The detour is
// an ordinary Shadowsocks inbound bound to loopback, and it owns per-user
// credentials and traffic accounting — which is what lets a ShadowTLS node
// support the same live user add/remove as every other protocol.
//
// The returned slice is ordered detour-first so the chain target exists
// before the public listener starts accepting connections.
func buildShadowTLSInbounds(tag string, info *panel.NodeInfo, c *conf.Options) ([]option.Inbound, error) {
	if info.ShadowTLS == nil {
		return nil, fmt.Errorf("missing shadowtls node settings")
	}
	n := info.ShadowTLS

	version := n.Version
	handshakeServer := n.Handshake.Server
	handshakePort := uint16(n.Handshake.ServerPort)
	strictMode := n.StrictMode
	wildcardSNI := n.WildcardSNI
	if o := c.SingOptions.ShadowTLSOptions; o != nil {
		if o.Version != 0 {
			version = o.Version
		}
		if o.HandshakeServer != "" {
			handshakeServer = o.HandshakeServer
		}
		if o.HandshakeServerPort != 0 {
			handshakePort = o.HandshakeServerPort
		}
		if o.StrictMode {
			strictMode = true
		}
		if o.WildcardSNI != "" {
			wildcardSNI = o.WildcardSNI
		}
	}
	if handshakeServer == "" {
		return nil, fmt.Errorf("shadowtls requires a handshake server")
	}
	if handshakePort == 0 {
		handshakePort = 443
	}

	listen, err := buildListenOptions(info, c)
	if err != nil {
		return nil, err
	}
	// Chain the public listener to the internal Shadowsocks inbound.
	listen.InboundOptions.Detour = detourTag(tag)

	shadowTLSOptions := &option.ShadowTLSInboundOptions{
		ListenOptions: listen,
		Version:       version,
		Handshake: option.ShadowTLSHandshakeOptions{
			ServerOptions: option.ServerOptions{
				Server:     handshakeServer,
				ServerPort: handshakePort,
			},
		},
		StrictMode:  strictMode,
		WildcardSNI: parseWildcardSNI(wildcardSNI),
	}
	// v2 authenticates with a single shared password; v3 uses a user list.
	switch version {
	case 3:
		shadowTLSOptions.Users = []option.ShadowTLSUser{{
			Name:     tag,
			Password: n.Password,
		}}
	case 2:
		shadowTLSOptions.Password = n.Password
	}

	detourListen, err := buildDetourListenOptions(c)
	if err != nil {
		return nil, err
	}
	detour := option.Inbound{
		Tag:     detourTag(tag),
		Type:    "shadowsocks",
		Options: buildShadowsocksOptions(detourListen, n.Cipher, n.ServerKey, buildMultiplex(c)),
	}
	public := option.Inbound{
		Tag:     tag,
		Type:    "shadowtls",
		Options: shadowTLSOptions,
	}
	return []option.Inbound{detour, public}, nil
}

// buildDetourListenOptions returns listen options for an internal inbound.
//
// sing-box always opens a socket for an inbound, even one that is only ever
// reached through a detour, so the detour is pinned to loopback on an
// ephemeral port where it is unreachable from outside the host.
func buildDetourListenOptions(c *conf.Options) (option.ListenOptions, error) {
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	return option.ListenOptions{
		Listen:     (*badoption.Addr)(&loopback),
		ListenPort: 0,
		InboundOptions: option.InboundOptions{
			SniffEnabled:             c.SingOptions.SniffEnabled,
			SniffOverrideDestination: c.SingOptions.SniffOverrideDestination,
			DomainStrategy:           parseDomainStrategy(c.SingOptions.DomainStrategy),
		},
	}, nil
}
