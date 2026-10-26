package xray

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

type protocolFixture struct {
	core                            *Xray
	info                            *panel.NodeInfo
	address, target, tag, publicKey string
	roots                           *x509.CertPool
	payload                         []byte
	certPEM                         []byte
	users                           []panel.UserInfo
}

func newProtocolFixture(t *testing.T, info *panel.NodeInfo) *protocolFixture {
	t.Helper()
	initLimiterOnce.Do(limiter.Init)
	f := &protocolFixture{info: info, tag: "protocol-" + t.Name(), payload: bytes.Repeat([]byte("verified-protocol-https"), 16384), users: []panel.UserInfo{{Id: 101, Uuid: singMuxTestPassword}, {Id: 102, Uuid: "22222222-2222-2222-2222-222222222222"}}}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(f.payload) }))
	origin.EnableHTTP2 = true
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	f.target = origin.Listener.Addr().String()
	f.roots = x509.NewCertPool()
	f.roots.AddCert(origin.Certificate())
	dir := t.TempDir()
	f.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.TLS.Certificates[0].Certificate[0]})
	key, err := x509.MarshalPKCS8PrivateKey(origin.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certFile, f.certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "outbounds.json")
	// Loopback is explicitly allowed only for this isolated test origin.
	if err = os.WriteFile(outFile, []byte(`[{"protocol":"freedom","tag":"fixture-direct","settings":{"finalRules":[{"action":"allow"}]}}]`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := conf.NewXrayConfig()
	if os.Getenv("N2X_PROTOCOL_TEST_DEBUG") == "1" {
		cfg.LogConfig.Level = "debug"
	}
	cfg.OutboundConfigPath = outFile
	instance, err := New(&conf.CoreConfig{XrayConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	f.core = instance.(*Xray)
	if err = f.core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.core.Close() })
	port := freeLoopbackPort(t)
	info.Common = &panel.CommonNode{ServerPort: port}
	f.address = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if info.Security == panel.Reality {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		host, p, err := net.SplitHostPort(f.target)
		if err != nil {
			t.Fatal(err)
		}
		f.publicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		settings := panel.TlsSettings{ServerName: "n2x.test", Dest: host, ServerPort: p, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortId: "0123456789abcdef"}
		if info.AnyTls != nil {
			info.AnyTls.TlsSettings = settings
		}
		if info.VAllss != nil {
			info.VAllss.TlsSettings = settings
		}
	}
	options := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertFile: certFile, KeyFile: keyFile}}
	if err = f.core.AddNode(f.tag, info, options); err != nil {
		t.Fatal(err)
	}
	limiter.AddLimiter(f.tag, &conf.LimitConfig{}, f.users, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(f.tag) })
	if _, err = f.core.AddUsers(&vCore.AddUsersParams{Tag: f.tag, NodeInfo: info, Users: f.users}); err != nil {
		t.Fatal(err)
	}
	expectedUsers := int64(len(f.users))
	if info.Type == "shadowsocks" {
		// buildShadowsocks starts the inbound with one random scaffold user;
		// the panel's two actual users are added alongside it.
		expectedUsers++
	}
	f.waitUsers(t, expectedUsers)
	return f
}
func (f *protocolFixture) waitUsers(t *testing.T, want int64) {
	t.Helper()
	manager, err := f.core.GetUserManager(f.tag)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if manager.GetUsersCount(context.Background()) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("user count=%d, want %d", manager.GetUsersCount(context.Background()), want)
}
func (f *protocolFixture) https(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	secure := tls.Client(conn, &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	defer secure.Close()
	if err := secure.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("inner TLS handshake: %w", err)
	}
	if _, err := io.WriteString(secure, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		return fmt.Errorf("HTTPS response headers: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("HTTPS body at %d bytes: %w", len(body), err)
	}
	if response.StatusCode != 200 || !bytes.Equal(body, f.payload) {
		return fmt.Errorf("HTTPS response mismatch: status=%d bytes=%d", response.StatusCode, len(body))
	}
	return nil
}
func (f *protocolFixture) checkTraffic(t *testing.T, uid int, minDownload int64) {
	t.Helper()
	traffic, err := f.core.GetUserTrafficSlice(f.tag, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range traffic {
		if entry.UID == uid && entry.Upload > 0 && entry.Download >= minDownload {
			return
		}
	}
	t.Fatalf("missing traffic for user %d: %+v", uid, traffic)
}
