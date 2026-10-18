package dispatcher

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
)

func onlineTestLimiter(t *testing.T) *limiter.Limiter {
	t.Helper()
	limiter.Init()
	l := limiter.AddLimiter(t.Name(), &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "uuid-1"}}, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(t.Name()) })
	return l
}

func TestGetLinkHalfCloseKeepsOnlineIPUntilResponseCloses(t *testing.T) {
	l := onlineTestLimiter(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag: t.Name(), User: &protocol.MemoryUser{Email: format.UserTag(t.Name(), "uuid-1")},
		Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 1234),
	})
	d := new(DefaultDispatcher)
	inbound, outbound, _, err := d.getLink(ctx, net.Network_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := outbound.Reader.(*pipe.Reader); !ok {
		t.Fatal("online tracking replaced the concrete pipe reader required by mux")
	}
	common.Close(inbound.Writer)
	if got := l.CountOnlineIP(); got != 1 {
		t.Fatalf("request half-close removed an active download: %d", got)
	}
	common.Close(outbound.Writer)
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("response close left %d online IPs", got)
	}
}

func TestManagedWriterReleasesOnlineIPOnEveryExit(t *testing.T) {
	for _, exit := range []string{"close", "interrupt", "cancel"} {
		t.Run(exit, func(t *testing.T) {
			l := onlineTestLimiter(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
			writer := &ManagedWriter{writer: buf.Discard, manager: manager}
			writer.trackOnline(ctx, l, format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
			manager.AddLink(writer, nil)
			if got := l.CountOnlineIP(); got != 1 {
				t.Fatalf("admitted connection has %d online IPs", got)
			}
			switch exit {
			case "close":
				writer.Close()
			case "interrupt":
				writer.Interrupt()
			case "cancel":
				cancel()
			}
			deadline := time.After(time.Second)
			for l.CountOnlineIP() != 0 {
				select {
				case <-deadline:
					t.Fatal("connection exit left an online IP")
				default:
					runtime.Gosched()
				}
			}
			writer.Close()
			writer.Interrupt()
		})
	}
}

func TestLinkManagerCloseAllAllowsConcurrentCleanup(t *testing.T) {
	l := onlineTestLimiter(t)
	manager := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	var workers sync.WaitGroup
	for range 32 {
		writer := &ManagedWriter{writer: buf.Discard, manager: manager}
		writer.trackOnline(context.Background(), l, format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
		manager.AddLink(writer, nil)
		workers.Go(func() { writer.Close() })
	}
	manager.CloseAll()
	workers.Wait()
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("bulk close left %d online IPs", got)
	}
}
