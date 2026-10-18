package sing

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type closeErrorPacketConn struct{ N.PacketConn }

func (*closeErrorPacketConn) Close() error { return net.ErrClosed }

func TestRoutedConnectionsReleaseAuthenticatedOnlineIP(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			l := limiter.AddLimiter(t.Name(), &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "uuid-1"}}, nil)
			t.Cleanup(func() { limiter.DeleteLimiter(t.Name()) })
			metadata := adapter.InboundContext{
				Inbound: t.Name(), User: "uuid-1",
				Source: M.ParseSocksaddr("192.0.2.1:1234"), Destination: M.ParseSocksaddr("192.0.2.2:443"),
			}
			hook := newHookServer()
			var close func() error
			if kind == "tcp" {
				conn, peer := net.Pipe()
				t.Cleanup(func() { peer.Close() })
				wrapped := hook.RoutedConnection(context.Background(), conn, metadata, nil, nil)
				close = wrapped.Close
			} else {
				wrapped := hook.RoutedPacketConnection(context.Background(), &closeErrorPacketConn{}, metadata, nil, nil)
				close = wrapped.Close
			}
			devices, err := l.GetOnlineDevice()
			if err != nil || len(*devices) != 1 || (*devices)[0] != (panel.OnlineUser{UID: 1, IP: "192.0.2.1"}) {
				t.Fatalf("authenticated source not reported: %v, %v", devices, err)
			}
			if err := close(); kind == "udp" && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("underlying close error was lost: %v", err)
			}
			close()
			if got := l.CountOnlineIP(); got != 0 {
				t.Fatalf("closed %s connection left %d online IPs", kind, got)
			}
		})
	}
}
