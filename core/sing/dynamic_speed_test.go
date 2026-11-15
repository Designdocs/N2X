package sing

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dynamicPacketSink struct {
	N.PacketConn
	bytes int
}

func (p *dynamicPacketSink) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	p.bytes += b.Len()
	b.Release()
	return nil
}
func (*dynamicPacketSink) Close() error { return nil }

func TestDynamicSpeedSingTCPAndUDPSharesCapAndKeepsBilling(t *testing.T) {
	limiter.Init()
	tag := t.Name()
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "user"}}, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	metadata := adapter.InboundContext{Inbound: tag, User: "user", Source: M.ParseSocksaddr("192.0.2.1:1234"), Destination: M.ParseSocksaddr("192.0.2.2:443")}
	hook := newHookServer()
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wrapped := hook.RoutedConnection(ctx, conn, metadata, nil, nil)
	defer wrapped.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	sink := &dynamicPacketSink{}
	packets := hook.RoutedPacketConnection(ctx, sink, metadata, nil, nil)
	defer packets.Close()
	b, reject := l.CheckLimit(format.UserTag(tag, "user"), "192.0.2.1", true, true)
	if reject {
		t.Fatal("user rejected")
	}
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 2, SustainSeconds: 30, LimitMbps: 1, PenaltySeconds: 60}
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 6 {
		b.Account(3 * 1000000 / 8 * 5)
		now = now.Add(5 * time.Second)
		l.SampleDynamic(now)
	}
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("penalty not created")
	}
	start := time.Now()
	if _, err := wrapped.Write(bytes.Repeat([]byte("t"), 65536)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		packet := buf.NewSize(32768)
		_, _ = packet.Write(bytes.Repeat([]byte("u"), 32768))
		if err := packets.WritePacket(packet, metadata.Destination); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("UDP/TCP bypassed combined cap: %v", elapsed)
	}
	if sink.bytes != 65536 {
		t.Fatalf("datagrams changed: %d", sink.bytes)
	}
	storage := hook.storageFor(tag, "user")
	if got := storage.DownCounter.Swap(0); got != 131072 {
		t.Fatalf("billed bytes=%d", got)
	}
	total := b.Total()
	l.SampleDynamic(now.Add(5 * time.Second))
	if b.Total() != total {
		t.Fatal("billing drain reset detection counter")
	}
	p.Enabled = false
	p.Revision++
	_ = l.ConfigureDynamic(p, nil, "")
	if b.Rate() != 0 {
		t.Fatal("disable did not reach existing TCP and UDP handles")
	}
}

func TestDynamicSpeedConcurrentSingBillingDrainsDoNotLoseBytes(t *testing.T) {
	tag := t.Name()
	core, _ := startMuxTrojanNode(t, tag, nil)
	storage := core.hookServer.storageFor(tag, lifecycleUsers[0].Uuid)
	done := make(chan struct{})
	go func() {
		for range 100000 {
			storage.UpCounter.Add(1)
			storage.DownCounter.Add(2)
		}
		close(done)
	}()
	var up, down int64
	for {
		traffic, err := core.GetUserTrafficSlice(tag, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range traffic {
			up += entry.Upload
			down += entry.Download
		}
		select {
		case <-done:
			up += storage.UpCounter.Swap(0)
			down += storage.DownCounter.Swap(0)
			if up != 100000 || down != 200000 {
				t.Fatalf("billing lost bytes: %d/%d", up, down)
			}
			return
		default:
			runtime.Gosched()
		}
	}
}
