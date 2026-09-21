package panel

import (
	"context"
	"net"
	"net/http"
	"time"
)

// panelDialTimeout bounds a single TCP attempt so an unreachable IPv4 path
// (e.g. a host whose A record points at a firewalled address) costs at most
// this long before we fall back to IPv6.
const panelDialTimeout = 5 * time.Second

// newPanelDialContext builds the dialer every panel connection (resty HTTP and
// the WebSocket driver) goes through.
//
// Go's default dialer runs Happy Eyeballs and, on a dual-stack machine,
// usually ends up on IPv6. The panel identifies a backend by the source IP it
// sees, and admins expect that to be the machine's IPv4. So we try IPv4 first
// and only fall back to IPv6 when the IPv4 attempt fails (no A record, route
// down, refused). A host with no AAAA record simply fails the second attempt
// with the same error it would have had before.
//
// When ApiSendIP is configured the address family is fixed by that local IP:
// a v4 send address can only dial tcp4 and vice versa, so there is nothing to
// prefer and we honour the operator's choice exactly.
func newPanelDialContext(sendIP string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: panelDialTimeout, KeepAlive: 30 * time.Second}

	if ip := net.ParseIP(sendIP); ip != nil {
		base.LocalAddr = &net.TCPAddr{IP: ip}
		network := "tcp6"
		if ip.To4() != nil {
			network = "tcp4"
		}
		return func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return base.DialContext(ctx, network, addr)
		}
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Only plain "tcp" is ambiguous; a caller that already pinned a
		// family keeps it.
		if network != "tcp" {
			return base.DialContext(ctx, network, addr)
		}
		conn, err4 := base.DialContext(ctx, "tcp4", addr)
		if err4 == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err4
		}
		conn, err6 := base.DialContext(ctx, "tcp6", addr)
		if err6 == nil {
			return conn, nil
		}
		// Report the IPv4 failure: that is the path the operator expects to
		// work, and it is the more useful error when both are down.
		return nil, err4
	}
}

// newPanelTransport clones the default transport with the IPv4-first dialer
// so resty keeps its usual proxy / TLS / HTTP2 behaviour.
func newPanelTransport(sendIP string) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = newPanelDialContext(sendIP)
	return tr
}
