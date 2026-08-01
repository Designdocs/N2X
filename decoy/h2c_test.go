package decoy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// startTestServer runs a decoy server on an ephemeral loopback port. The
// listener is injected so the test does not have to race for a free port, and
// ValidateListenAddress can keep rejecting port 0 in real configuration.
func startTestServer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := newServer(listener, contentProfileBalanced)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve() }()

	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown(): %v", err)
		}
		if err := <-serveResult; err != nil {
			t.Errorf("Serve(): %v", err)
		}
	})

	return listener.Addr().String()
}

func TestServerServesHTTP11(t *testing.T) {
	t.Parallel()

	address := startTestServer(t)
	response, err := http.Get("http://" + address + "/?profile=web")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if response.ProtoMajor != 1 {
		t.Fatalf("proto = %s, want HTTP/1.x", response.Proto)
	}
	if !strings.Contains(string(body), "Ideas for slower mornings") {
		t.Fatal("body is not the web profile page")
	}
}

// A browser reaching the node over TLS negotiates h2, and Xray forwards those
// frames to the fallback destination unwrapped. Without h2c the listener would
// answer the HTTP/2 preface with an HTTP/1.1 400 and the browser would show
// ERR_HTTP2_PROTOCOL_ERROR instead of the decoy site.
func TestServerServesPriorKnowledgeHTTP2(t *testing.T) {
	t.Parallel()

	address := startTestServer(t)
	client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}

	response, err := client.Get("http://" + address + "/?profile=media")
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2", response.Proto)
	}
	if !strings.Contains(string(body), "Continue listening") {
		t.Fatal("body is not the media profile page")
	}
}
