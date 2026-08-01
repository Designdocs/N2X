package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/decoyfallback"

	_ "github.com/Designdocs/N2X/core/xray/distro/all"
)

// freeLoopbackPort reserves a port and releases it. The companion web service
// refuses a zero port on purpose, so there is nothing to bind to lazily.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

func waitForListener(t *testing.T, address string) {
	t.Helper()
	for range 100 {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing is listening on %s", address)
}

func startDecoyService(t *testing.T) string {
	t.Helper()
	address := fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort(t))

	service, err := decoy.NewServer(decoy.Config{ListenAddress: address, DefaultProfile: "media"})
	if err != nil {
		t.Fatalf("decoy.NewServer() error = %v", err)
	}
	go func() {
		if err := service.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("companion web service stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})

	waitForListener(t, address)
	return address
}

func startXrayWithInbound(t *testing.T, inbound *core.InboundHandlerConfig) {
	t.Helper()

	outbound, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: "direct"}).Build()
	if err != nil {
		t.Fatalf("build the outbound: %v", err)
	}

	server, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound:  []*core.InboundHandlerConfig{inbound},
		Outbound: []*core.OutboundHandlerConfig{outbound},
	})
	if err != nil {
		t.Fatalf("core.New() error = %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("server.Start() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
}

// The whole chain with nothing stubbed: the real companion web service, the
// real N2X config builder, and a real Xray core carrying an xhttp inbound.
//
// TLS is left off because the transport decides Host and Path long after the
// handshake, so it changes nothing here and would only add certificate setup.
func TestXhttpNodeServesTheDecoyToABrowser(t *testing.T) {
	decoyAddress := startDecoyService(t)
	t.Setenv(decoy.ListenAddressEnvironment, decoyAddress)
	t.Setenv(decoyfallback.OriginEnvironment, "")

	nodePort := freeLoopbackPort(t)
	inbound, err := buildInbound(
		&conf.Options{
			ListenIP:    "127.0.0.1",
			XrayOptions: &conf.XrayOptions{DecoyFallback: true},
		},
		&panel.NodeInfo{
			Type:   "vless",
			Common: &panel.CommonNode{ServerPort: nodePort},
			VAllss: &panel.VAllssNode{
				Network:         "xhttp",
				NetworkSettings: json.RawMessage(`{"path":"/xh8k2m"}`),
			},
		},
		"e2e",
	)
	if err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
	if !decoyfallback.Enabled() {
		t.Fatal("the core reports no usable decoy origin after buildInbound")
	}

	startXrayWithInbound(t, inbound)
	nodeAddress := fmt.Sprintf("127.0.0.1:%d", nodePort)
	waitForListener(t, nodeAddress)

	client := &http.Client{Timeout: 5 * time.Second}
	get := func(path string) (int, string, string) {
		t.Helper()
		response, err := client.Get("http://" + nodeAddress + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return response.StatusCode, response.Header.Get("Content-Type"), string(body)
	}

	// A bare 404 on every path is the signal this feature exists to remove, so
	// a scanner probe must get the site's own 404 rather than an empty one.
	for _, path := range []string{"/", "/robots.txt", "/wp-admin", "/.env"} {
		status, contentType, body := get(path)
		if status == http.StatusNotFound && body == "" {
			t.Fatalf("%s returned the bare 404 the fallback exists to remove", path)
		}
		if status >= http.StatusInternalServerError {
			t.Fatalf("%s = %d %s", path, status, contentType)
		}
	}

	status, contentType, body := get("/")
	if status != http.StatusOK ||
		!strings.Contains(contentType, "text/html") ||
		!strings.Contains(body, "<!doctype html>") {
		t.Fatalf("/ = %d %s %.80s, want the decoy home page", status, contentType, body)
	}

	// The proxy path must be untouched: a request under the node's own path
	// belongs to xhttp and must never be reverse proxied to the decoy.
	if _, _, body := get("/xh8k2m/probe"); strings.Contains(body, "<!doctype html>") {
		t.Fatal("a request on the node's own path was served the decoy; the transport hook swallowed proxy traffic")
	}
}

// Without the switch the node keeps the empty 404 it had before, so an operator
// who never opts in sees no behaviour change.
func TestXhttpNodeWithoutDecoyFallbackStillReturns404(t *testing.T) {
	t.Setenv(decoy.ListenAddressEnvironment, "")
	t.Setenv(decoyfallback.OriginEnvironment, "")

	nodePort := freeLoopbackPort(t)
	inbound, err := buildInbound(
		&conf.Options{ListenIP: "127.0.0.1", XrayOptions: &conf.XrayOptions{}},
		&panel.NodeInfo{
			Type:   "vless",
			Common: &panel.CommonNode{ServerPort: nodePort},
			VAllss: &panel.VAllssNode{
				Network:         "xhttp",
				NetworkSettings: json.RawMessage(`{"path":"/xh8k2m"}`),
			},
		},
		"e2e",
	)
	if err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}

	startXrayWithInbound(t, inbound)
	nodeAddress := fmt.Sprintf("127.0.0.1:%d", nodePort)
	waitForListener(t, nodeAddress)

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + nodeAddress + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read /: %v", err)
	}

	if response.StatusCode != http.StatusNotFound || len(body) != 0 {
		t.Fatalf("/ = %d %q, want an empty 404", response.StatusCode, body)
	}
}
