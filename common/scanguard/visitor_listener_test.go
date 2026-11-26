package scanguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

func relayTestCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"n2x-relay.invalid"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, leaf
}

func TestUntrustedRelayCertificate(t *testing.T) {
	credential, _ := relayTestCert(t)
	client, server := net.Pipe()
	defer client.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := server.Write([]byte(visitorMagic)); err != nil {
			serverDone <- err
			return
		}
		serverDone <- tls.Server(server, &tls.Config{Certificates: []tls.Certificate{credential}}).Handshake()
	}()
	listener := &visitorListener{tag: t.Name(), enforce: true, roots: x509.NewCertPool()}
	conn, err := listener.identify(client)
	var unknown x509.UnknownAuthorityError
	if conn != nil || !errors.As(err, &unknown) {
		t.Fatalf("expected untrusted certificate rejection, got %v", err)
	}
	if err := <-serverDone; err == nil {
		t.Fatal("untrusted relay completed handshake")
	}
}

// Endpoint addresses are explicit so the same test covers IPv4-mapped
// addresses and a translated destination without configuring host aliases.
type testRelaySocket struct{ net.Conn }

func (testRelaySocket) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
}
func (testRelaySocket) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 10443}
}

func TestAmbiguousVisitorTransfersWithoutBanIdentity(t *testing.T) {
	credential, leaf := relayTestCert(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, tc := range []struct {
		name, visitor, target string
		enabled               bool
	}{
		{"same-as-relay", "192.0.2.1", "192.0.2.2:10443", true},
		{"translated-target", "192.0.2.3", "192.0.2.10:10443", true},
		{"disabled", "192.0.2.3", "192.0.2.2:10443", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				if _, err := io.WriteString(server, visitorMagic); err != nil {
					done <- err
					return
				}
				channel := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{credential}})
				ip := netip.MustParseAddr(tc.visitor).As16()
				frame := append(ip[:], byte(len(tc.target)))
				frame = append(frame, tc.target...)
				_, err := channel.Write(append(frame, 'A'))
				done <- err
			}()
			listener := visitorListener{tag: t.Name(), enforce: tc.enabled, roots: roots}
			conn, err := listener.identify(testRelaySocket{client})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := conn.(*visitorConn); ok {
				t.Fatal("assigned ban identity to an ambiguous connection")
			}
			var payload [1]byte
			if _, err := io.ReadFull(conn, payload[:]); err != nil || payload[0] != 'A' {
				t.Fatalf("transfer failed: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
