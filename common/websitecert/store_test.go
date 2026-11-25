package websitecert

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/decoy"
)

func TestManagedDecoyHTTPSReusesAndReloadsCertificates(t *testing.T) {
	now := time.Now()
	root := issueDecoyTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, nil)
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	store := &Store{directory: t.TempDir(), roots: roots}
	refreshOnNextHandshake := func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.refreshAt = time.Time{}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	server, err := decoy.NewServer(decoy.Config{
		ListenAddress: address,
		TLS:           &decoy.TLSFiles{GetCertificate: store.GetCertificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	handshake := func(host string, wantSerial int64) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{
			ServerName: host,
			RootCAs:    roots,
		})
		if err != nil && wantSerial == 0 {
			return
		}
		if err != nil {
			t.Fatalf("connect to %s: %v", host, err)
		}
		defer conn.Close()
		state := conn.ConnectionState()
		if got := state.PeerCertificates[0].SerialNumber.Int64(); got != wantSerial || state.Version != tls.VersionTLS13 {
			t.Fatalf("%s negotiated TLS %#x with certificate %d, want TLS 1.3 and certificate %d", host, state.Version, got, wantSerial)
		}
	}

	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(store.directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	leaf := func(name string, serial int64, issuer *decoyTestCertificate, expires time.Time) *decoyTestCertificate {
		return issueDecoyTestCertificate(t, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			DNSNames:     []string{name},
			NotBefore:    now.Add(-12 * time.Hour),
			NotAfter:     expires,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, issuer)
	}
	validUntil := now.Add(12 * time.Hour)

	const host = "node.example.test"
	handshake(host, 0)
	exact := leaf(host, 2, root, validUntil)
	write("fullchain-node.example.test.cer", exact.certPEM)
	write("cert-node.example.test.key", exact.keyPEM)
	wildcard := leaf("*.web.example.test", 3, root, validUntil)
	write("fullchain-wildcard.web.example.test.cer", wildcard.certPEM)
	write("cert-wildcard.web.example.test.key", wildcard.keyPEM)
	legacy := leaf("legacy.example.test", 4, root, validUntil)
	write("fullchain.cer", legacy.certPEM)
	write("cert.key", legacy.keyPEM)
	untrusted := leaf("untrusted.example.test", 5, nil, validUntil)
	write("fullchain-untrusted.example.test.cer", untrusted.certPEM)
	write("cert-untrusted.example.test.key", untrusted.keyPEM)
	expired := leaf("expired.example.test", 6, root, now.Add(-time.Hour))
	write("fullchain-expired.example.test.cer", expired.certPEM)
	write("cert-expired.example.test.key", expired.keyPEM)

	refreshOnNextHandshake()
	handshake(host, 2)
	handshake("page.web.example.test", 3)
	handshake("legacy.example.test", 4)
	for _, name := range []string{"outside.example.test", "nested.page.web.example.test", "untrusted.example.test", "expired.example.test"} {
		hello := &tls.ClientHelloInfo{ServerName: name, SupportedVersions: []uint16{tls.VersionTLS13}}
		if _, err := store.GetCertificate(hello); err == nil {
			t.Errorf("selected a certificate for %q", name)
		}
	}

	// ACME can publish the renewed chain and key in separate writes.
	renewed := leaf(host, 7, root, validUntil)
	write("fullchain-node.example.test.cer", renewed.certPEM)
	refreshOnNextHandshake()
	handshake(host, 2)
	write("cert-node.example.test.key", renewed.keyPEM)
	refreshOnNextHandshake()
	handshake(host, 7)
}

type decoyTestCertificate struct {
	cert    *x509.Certificate
	key     ed25519.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

func issueDecoyTestCertificate(t *testing.T, template *x509.Certificate, issuer *decoyTestCertificate) *decoyTestCertificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent, signingKey := template, private
	if issuer != nil {
		parent, signingKey = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return &decoyTestCertificate{
		cert:    certificate,
		key:     private,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}
