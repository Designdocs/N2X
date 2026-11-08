package xray

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Use the real Xray SOCKS and HTTP clients against in-memory proxies.
// No socket, panel, DNS resolver, or external service is needed.
func TestOutboundReloadPreservesProxyConnections(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	t.Setenv("XRAY_DNS_PATH", "")
	dialer := new(testOutboundDialer)
	internet.UseAlternativeSystemDialer(dialer)
	t.Cleanup(func() {
		dialer.close()
		internet.UseAlternativeSystemDialer(nil)
	})
	outboundPath := filepath.Join(dir, "custom_outbound.json")
	routePath := filepath.Join(dir, "route.json")
	configPath := filepath.Join(dir, "config.json")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(routePath, `{"rules":[{"type":"field","domain":["full:check.example"],"outboundTag":"unlock"}]}`)
	write(configPath, fmt.Sprintf(`{
		"Cores": [{"Type":"xray","AssetPath":%q,"RouteConfigPath":%q,"OutboundConfigPath":%q}],
		"Nodes": [{"Core":"xray","ApiHost":"http://127.0.0.1:1","ApiKey":"test","NodeID":1,"NodeType":"vless"}]
	}`, dir, routePath, outboundPath))
	socks := func(port int) string {
		return fmt.Sprintf(`{"tag":"unlock","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%d}]}}`, port)
	}
	const keep = `{"tag":"direct","protocol":"freedom"}`
	load := func(body string) *conf.Conf {
		t.Helper()
		write(outboundPath, body)
		config, err := conf.LoadValidated(configPath, conf.ValidateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	initial := load("[" + keep + "," + socks(10001) + "]")
	running, err := New(&initial.CoresConfig[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Close() })
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	xray := running.(*Xray)
	unchanged := xray.ohm.GetHandler("direct")
	open := func() net.Conn {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "test"})
		conn, err := core.Dial(ctx, xray.Server, xnet.TCPDestination(xnet.DomainAddress("check.example"), 443))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	probe := func(conn net.Conn, want byte) {
		t.Helper()
		result := make(chan error, 1)
		go func() {
			if _, err := conn.Write([]byte{'!'}); err != nil {
				result <- err
				return
			}
			var data [2]byte
			_, err := io.ReadFull(conn, data[:])
			if err == nil && data != [2]byte{want, '!'} {
				err = fmt.Errorf("got %q, want proxy %c", data, want)
			}
			result <- err
		}()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("timed out waiting for proxy %c", want)
		}
	}
	reload := func(c *conf.Conf) error {
		return vCore.ReloadOutbounds(running, c.CoresConfig, map[string]struct{}{outboundPath: {}})
	}

	first := open()
	probe(first, 'A')
	candidate := load("[" + keep + "," + socks(10002) + "]")
	write(outboundPath, `[{`)
	if err := reload(candidate); err != nil {
		t.Fatal(err)
	}
	if xray.ohm.GetHandler("direct") != unchanged {
		t.Fatal("unmodified outbound was replaced")
	}
	second := open()
	probe(first, 'A')
	probe(second, 'B')

	invalid := load("[" + keep + "," + socks(10001) + `,{"tag":"broken","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":0}]}}]`)
	if err := reload(invalid); err == nil {
		t.Fatal("invalid entry applied")
	}
	if err := reload(load("[" + keep + "]")); err == nil {
		t.Fatal("removed an outbound still referenced by the router")
	}
	probe(first, 'A')
	probe(second, 'B')
	probe(open(), 'B')

	const httpOutbound = `{"tag":"unlock","protocol":"http","settings":{"servers":[{"address":"127.0.0.1","port":10003}]}}`
	if err := reload(load("[" + keep + "," + httpOutbound + "]")); err != nil {
		t.Fatal(err)
	}
	probe(second, 'B')
	probe(open(), 'C')
}

type testOutboundDialer struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (d *testOutboundDialer) DestIpAddress() xnet.IP { return nil }

func (d *testOutboundDialer) Dial(_ context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	if dest.Port < 10001 || dest.Port > 10003 {
		return nil, fmt.Errorf("unexpected dial to %s", dest)
	}
	client, peer := net.Pipe()
	d.mu.Lock()
	d.peers = append(d.peers, peer)
	d.mu.Unlock()
	go func() {
		defer peer.Close()
		var input io.Reader = peer
		if dest.Port == 10003 {
			reader := bufio.NewReader(peer)
			request, err := http.ReadRequest(reader)
			if err != nil || request.Method != "CONNECT" {
				return
			}
			if _, err := io.WriteString(peer, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
				return
			}
			input = reader
		} else if err := acceptOutboundTestSOCKS(peer); err != nil {
			return
		}
		response := [2]byte{'A' + byte(dest.Port-10001), 0}
		for {
			if _, err := io.ReadFull(input, response[1:]); err != nil {
				return
			}
			if _, err := peer.Write(response[:]); err != nil {
				return
			}
		}
	}()
	return client, nil
}

func acceptOutboundTestSOCKS(peer net.Conn) error {
	var greeting [2]byte
	if _, err := io.ReadFull(peer, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 {
		return fmt.Errorf("unexpected SOCKS version %d", greeting[0])
	}
	if _, err := io.CopyN(io.Discard, peer, int64(greeting[1])); err != nil {
		return err
	}
	if _, err := peer.Write([]byte{5, 0}); err != nil {
		return err
	}
	var request [5]byte
	if _, err := io.ReadFull(peer, request[:]); err != nil {
		return err
	}
	if request[3] != 3 {
		return fmt.Errorf("unexpected SOCKS address type %d", request[3])
	}
	if _, err := io.CopyN(io.Discard, peer, int64(request[4])+2); err != nil {
		return err
	}
	_, err := peer.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	return err
}

func (d *testOutboundDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, peer := range d.peers {
		_ = peer.Close()
	}
}

type testDrainHandler struct {
	tag     string
	entered chan struct{}
	resume  chan struct{}
	closed  atomic.Int32
}

func (h *testDrainHandler) Tag() string { return h.tag }
func (*testDrainHandler) Start() error  { return nil }
func (h *testDrainHandler) Close() error {
	h.closed.Add(1)
	return nil
}
func (*testDrainHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*testDrainHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *testDrainHandler) Dispatch(context.Context, *transport.Link) {
	if h.entered != nil {
		h.entered <- struct{}{}
		<-h.resume
	}
}

func TestOutboundGenerationClosesAfterLastConnection(t *testing.T) {
	ctx := context.Background()
	manager, err := newOutboundManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	old := &testDrainHandler{tag: "unlock", entered: make(chan struct{}, 2), resume: make(chan struct{}, 2)}
	next := &testDrainHandler{tag: old.tag}
	publish := func(key string, handler outbound.Handler) {
		t.Helper()
		config := &core.OutboundHandlerConfig{Tag: handler.Tag(), ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}
		def := outboundDefinition{key: key, config: config, live: true}
		finish, err := manager.prepare([]outboundDefinition{def}, func(*core.OutboundHandlerConfig) (outbound.Handler, error) {
			return handler, nil
		}, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		finish(true)
	}
	publish("old", old)
	previous := manager.GetHandler(old.tag)
	var active sync.WaitGroup
	for range 2 {
		active.Go(func() { previous.Dispatch(ctx, &transport.Link{}) })
		<-old.entered
	}
	publish("new", next)
	if old.closed.Load() != 0 {
		t.Fatal("closed the old outbound while it was in use")
	}
	// Even a lookup that raced with publication cannot enter the retired handler.
	previous.Dispatch(ctx, &transport.Link{})
	old.resume <- struct{}{}
	old.resume <- struct{}{}
	active.Wait()
	if old.closed.Load() != 1 || next.closed.Load() != 0 {
		t.Fatalf("unexpected closes: old=%d new=%d", old.closed.Load(), next.closed.Load())
	}
}

func BenchmarkOutboundLookupAndDispatch(b *testing.B) {
	ctx := context.Background()
	m, err := newOutboundManager(ctx)
	if err != nil {
		b.Fatal(err)
	}
	h := &testDrainHandler{tag: "unlock"}
	if err := m.dynamic.AddHandler(ctx, h); err != nil {
		b.Fatal(err)
	}
	view := &outboundView{byTag: map[string]outbound.Handler{h.tag: &outboundGeneration{Handler: h, owner: m}}}
	m.view.Store(view)
	for _, item := range []struct {
		name    string
		manager outbound.Manager
	}{{"upstream", m.dynamic}, {"reloadable", m}} {
		b.Run(item.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				link := new(transport.Link)
				for pb.Next() {
					item.manager.GetHandler(h.tag).Dispatch(ctx, link)
				}
			})
		})
	}
}
