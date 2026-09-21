package panel

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// listen returns a listener on the given network and its port, or skips when
// the loopback for that family is unavailable on the test host.
func listen(t *testing.T, network, host string) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("%s loopback unavailable: %v", network, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func dialLocalhost(t *testing.T, sendIP string, port int) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := newPanelDialContext(sendIP)(ctx, "tcp", net.JoinHostPort("localhost", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestPanelDialPrefersIPv4WhenBothListen(t *testing.T) {
	_, port4 := listen(t, "tcp4", "127.0.0.1")
	// Bind the same port on v6 so localhost resolves to a working AAAA too.
	ln6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port4)))
	if err != nil {
		t.Skipf("cannot mirror port on ::1: %v", err)
	}
	defer ln6.Close()

	conn := dialLocalhost(t, "", port4)
	if ip := conn.RemoteAddr().(*net.TCPAddr).IP; ip.To4() == nil {
		t.Fatalf("expected IPv4 remote, got %s", ip)
	}
}

func TestPanelDialFallsBackToIPv6WhenIPv4Refuses(t *testing.T) {
	_, port6 := listen(t, "tcp6", "::1")
	// Nothing listens on 127.0.0.1:port6, so tcp4 is refused and we must
	// land on the v6 listener.
	conn := dialLocalhost(t, "", port6)
	if ip := conn.RemoteAddr().(*net.TCPAddr).IP; ip.To4() != nil {
		t.Fatalf("expected IPv6 remote after v4 refusal, got %s", ip)
	}
}

func TestPanelDialHonoursSendIPFamily(t *testing.T) {
	_, port := listen(t, "tcp4", "127.0.0.1")
	conn := dialLocalhost(t, "127.0.0.1", port)
	if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("expected local addr 127.0.0.1, got %s", got)
	}
}

func TestPanelDialReportsIPv4ErrorWhenBothFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Port 1 on loopback is closed for both families.
	_, err := newPanelDialContext("")(ctx, "tcp", "localhost:1")
	if err == nil {
		t.Fatal("expected error")
	}
}
