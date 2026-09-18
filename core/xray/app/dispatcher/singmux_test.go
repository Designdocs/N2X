package dispatcher

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestSingMuxDestinationRejectsEmptyTargets(t *testing.T) {
	for _, addr := range []metadata.Socksaddr{
		// A zero-length name is well formed on the wire.
		metadata.ParseSocksaddrHostPort("", 443),
		{Port: 443},
		{Fqdn: "example.com"},
	} {
		if dest, ok := singMuxDestination(net.Network_TCP, addr); ok {
			t.Fatalf("singMuxDestination(%#v) = %v, want rejection", addr, dest)
		}
	}
	for _, tc := range []struct {
		addr metadata.Socksaddr
		want string
	}{
		{metadata.Socksaddr{Fqdn: "example.com", Port: 443}, "udp:example.com:443"},
		{metadata.Socksaddr{Addr: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 53}, "udp:127.0.0.1:53"},
	} {
		dest, ok := singMuxDestination(net.Network_UDP, tc.addr)
		if !ok || dest.String() != tc.want {
			t.Fatalf("singMuxDestination(%v) = %v, %v; want %s", tc.addr, dest, ok, tc.want)
		}
	}
}

func TestSingMuxStreamsDoNotShareTheCarrierInbound(t *testing.T) {
	parent := &session.Inbound{Tag: "node", CanSpliceCopy: 1}
	ctx := session.ContextWithInbound(context.Background(), parent)
	first := session.InboundFromContext(newSingMuxStreamContext(ctx, nil))
	second := session.InboundFromContext(newSingMuxStreamContext(ctx, nil))
	if first == parent || second == parent || first == second {
		t.Fatal("mux streams alias an inbound")
	}
	if first.Tag != "node" || first.CanSpliceCopy != 3 || first.Conn != nil {
		t.Fatalf("stream inbound = %+v, want the node tag with splicing off", first)
	}
	if parent.CanSpliceCopy != 1 {
		t.Fatal("stream context rewrote the carrier inbound")
	}
}
