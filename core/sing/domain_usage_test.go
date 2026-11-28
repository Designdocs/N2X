package sing

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDomainUsageCountsSingTCPAndUDP(t *testing.T) {
	tag := t.Name()
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 9, DomainUserID: 2, Uuid: "demo"}}, nil)
	defer limiter.DeleteLimiter(tag)
	s, err := domainusage.Open(filepath.Join(t.TempDir(), "usage.db"), 0.5)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(time.Now())
	l.DomainUsage.Store(s)
	h := newHookServer()
	m := adapter.InboundContext{Inbound: tag, User: "demo", Source: M.ParseSocksaddr("127.0.0.1:4123"), Destination: M.ParseSocksaddr("cdn.example:443")}
	a, b := net.Pipe()
	go func() { io.Copy(io.Discard, b); b.Close() }()
	c := h.RoutedConnection(context.Background(), a, m, nil, nil)
	if _, err = c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	p := h.RoutedPacketConnection(context.Background(), &dynamicPacketSink{}, m, nil, nil)
	packet := buf.NewSize(4)
	packet.Write([]byte("abcd"))
	if err = p.WritePacket(packet, m.Destination); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.Flush(now); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.Query(2, now)
	if err != nil || len(rows) != 1 || rows[0] != (domainusage.Row{Host: "cdn.example", Raw: 7, Weighted: 3.5, Connections: 2}) {
		t.Fatalf("%+v: %v", rows, err)
	}
}
