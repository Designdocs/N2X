package xray

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/Designdocs/N2X/limiter"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDomainUsageCountsVMessSession(t *testing.T) {
	f := newProtocolFixture(t, &panel.NodeInfo{Type: "vmess", VAllss: &panel.VAllssNode{Network: "tcp"}})
	l, err := limiter.GetLimiter(f.tag)
	if err != nil {
		t.Fatal(err)
	}
	s, err := domainusage.Open(filepath.Join(t.TempDir(), "sample.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	l.DomainUsage.Store(s)
	defer func() { l.DomainUsage.Store(nil); s.Close(time.Now()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.address)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client, err := vmess.NewClient(f.users[0].Uuid, "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(f.target)
	conn, err := client.DialConn(raw, M.ParseSocksaddr(net.JoinHostPort("localhost", port)))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.https(ctx, conn); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.Flush(now); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.Query(f.users[0].Id, now)
	if err != nil || len(rows) != 1 || rows[0].Host != "localhost" || rows[0].Raw < int64(len(f.payload)) || rows[0].Weighted != 2*float64(rows[0].Raw) || rows[0].Connections != 1 {
		t.Fatalf("%+v: %v", rows, err)
	}
}
