package sing

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/decoy"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

func TestManagedSnellV6(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Run("direct", func(t *testing.T) { testManagedSnellV6(t, mode, "", false, false) })
			t.Run("shadowtls", func(t *testing.T) { testManagedSnellV6(t, mode, "localhost", false, false) })
			t.Run("website-fallback", func(t *testing.T) { testManagedSnellV6(t, mode, "127.0.0.1", false, false) })
			t.Run("built-in-website", func(t *testing.T) { testManagedSnellV6(t, mode, "127.0.0.1", true, false) })
			t.Run("direct-website", func(t *testing.T) { testManagedSnellV6(t, mode, "", true, true) })
		})
	}
}

func testManagedSnellV6(t *testing.T, mode snellv6.Mode, handshakeHost string, builtinWebsite, directWebsite bool) {
	tag := t.Name()
	const psk = "test-shared-key-12345"
	const outerKey = "test-shadowtls-key"
	sni := "example.com"
	pageText := "local handshake server"
	wrapped := handshakeHost != ""
	websiteFallback := handshakeHost == "127.0.0.1"
	server := newLifecycleCore(t)
	first, second := lifecycleUsers[0], lifecycleUsers[1]
	limiter.AddLimiter(tag, &conf.LimitConfig{}, lifecycleUsers, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	common := &panel.CommonNode{ServerPort: freePort(t)}
	info := &panel.NodeInfo{
		Type: "snell", Common: common,
		Snell: &panel.SnellNode{CommonNode: *common, Version: panel.SnellVersion, PSK: psk, Mode: mode.String()},
	}
	var cert []byte
	var webClient *http.Client
	if wrapped || directWebsite {
		var coverPort int
		if builtinWebsite {
			sni = "n2x.test"
			pageText = "Ideas for slower mornings"
			coverPort, cert, webClient = startSnellBuiltInWebsite(t, sni)
		} else {
			cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websiteFallback && r.TLS.ServerName != sni {
					http.Error(w, "unexpected SNI", http.StatusMisdirectedRequest)
					return
				}
				_, _ = io.WriteString(w, pageText)
			}))
			cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			cover.StartTLS()
			t.Cleanup(cover.Close)
			coverPort = cover.Listener.Addr().(*net.TCPAddr).Port
			cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cover.Certificate().Raw})
			webClient = cover.Client()
			if websiteFallback {
				webClient.Transport.(*http.Transport).TLSClientConfig.ServerName = sni
			}
		}
		webClient.Timeout = 3 * time.Second
		if directWebsite {
			info.Snell.WebsiteFallback = &panel.SnellWebsiteFallback{ServerName: sni, ServerPort: uint16(coverPort)}
		} else {
			info.Snell.ShadowTLS = &panel.SnellShadowTLS{
				Password: outerKey,
				Handshake: panel.ShadowTLSHandshake{
					Server:     handshakeHost,
					ServerPort: coverPort,
				},
			}
			if websiteFallback {
				info.Snell.ShadowTLS.FallbackServerName = sni
			}
		}
	}
	if err := server.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", common.ServerPort)
	var outerClient func(password string) *shadowtls.Outbound
	if wrapped {
		inner, found := server.box.Inbound().Get(tag)
		if !found || inner.(*snellInbound).listener != nil {
			t.Fatal("wrapped Snell must use the original node tag without a listening socket")
		}
		if outer, found := server.box.Inbound().Get(snellShadowTLSTag(tag)); !found || outer.Type() != "shadowtls" {
			t.Fatal("ShadowTLS did not own the public listener")
		}
		outerClient = func(password string) *shadowtls.Outbound {
			t.Helper()
			client, err := shadowtls.NewOutbound(server.ctx, server.router, log.NewNOPFactory().Logger(), "shadowtls-client",
				option.ShadowTLSOutboundOptions{
					Version:       3,
					Password:      password,
					ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(common.ServerPort)},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
						Enabled: true, ServerName: sni, MinVersion: "1.3", Certificate: []string{string(cert)},
					}},
				})
			if err != nil {
				t.Fatal(err)
			}
			return client.(*shadowtls.Outbound)
		}
	}
	if webClient != nil {
		resp, err := webClient.Get("https://" + address)
		if err != nil {
			t.Fatalf("ordinary TLS request: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), pageText) {
			t.Fatalf("expected the configured website with status 200, got %s (%v)", resp.Status, err)
		}
		if builtinWebsite && (resp.ProtoMajor != 2 || resp.TLS.Version != tls.VersionTLS13) {
			t.Fatalf("expected HTTP/2 over TLS 1.3, got %s over %s", resp.Proto, tls.VersionName(resp.TLS.Version))
		}
	}
	destination := M.ParseSocksaddr(startEchoServer(t))
	payload := []byte("snell echo")
	newClient := func(key string) *snellv6.Client {
		t.Helper()
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), Mode: mode, UserKey: []byte(key)})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	dialOuter := func(client *shadowtls.Outbound) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(server.ctx, 3*time.Second)
		defer cancel()
		return client.DialContext(ctx, "tcp", M.ParseSocksaddr(address))
	}
	var shadowClient *shadowtls.Outbound
	if wrapped {
		shadowClient = outerClient(outerKey)
	}
	dial := func() net.Conn {
		t.Helper()
		var conn net.Conn
		var err error
		if shadowClient != nil {
			conn, err = dialOuter(shadowClient)
		} else {
			conn, err = net.DialTimeout("tcp", address, 3*time.Second)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	tcp := func(key string) net.Conn {
		return newClient(key).DialEarlyConn(dial(), destination)
	}
	exchange := func(conn net.Conn) error {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		echo := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echo); err != nil {
			return err
		}
		if !bytes.Equal(echo, payload) {
			return fmt.Errorf("unexpected TCP echo: %q", echo)
		}
		return nil
	}
	assertDenied := func(key string) {
		t.Helper()
		conn := tcp(key)
		defer conn.Close()
		if err := exchange(conn); err == nil || os.IsTimeout(err) {
			t.Fatalf("expected immediate rejection, got %v", err)
		}
	}
	addUsers := func(users ...panel.UserInfo) {
		t.Helper()
		if _, err := server.AddUsers(&core.AddUsersParams{Tag: tag, NodeInfo: info, Users: users}); err != nil {
			t.Fatal(err)
		}
	}

	assertDenied("")
	assertDenied(first.Uuid)
	addUsers(first, second)
	assertDenied("")
	if wrapped {
		bad, err := dialOuter(outerClient("wrong-outer-password"))
		if err == nil {
			defer bad.Close()
			if err := bad.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if exchange(newClient(first.Uuid).DialEarlyConn(bad, destination)) == nil {
				t.Fatal("valid Snell credentials bypassed the ShadowTLS password")
			}
		}
	}
	active := tcp(first.Uuid)
	defer active.Close()
	if err := exchange(active); err != nil {
		t.Fatalf("TCP echo: %v", err)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpTarget.Close() })
	go func() {
		buffer := make([]byte, 256)
		if n, peer, err := udpTarget.ReadFromUDP(buffer); err == nil {
			_, _ = udpTarget.WriteToUDP(buffer[:n], peer)
		}
	}()
	udp, err := newClient(second.Uuid).DialPacketConn(dial())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err := udp.WriteTo(payload, udpTarget.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 256)
	if n, _, err := udp.ReadFrom(echo); err != nil || !bytes.Equal(echo[:n], payload) {
		t.Fatalf("UDP echo: %q, %v", echo[:n], err)
	}

	traffic, err := server.GetUserTrafficSlice(tag, true)
	if err != nil || len(traffic) != 2 {
		t.Fatalf("expected two traffic records, got %+v (%v)", traffic, err)
	}
	for _, entry := range traffic {
		if (entry.UID != first.Id && entry.UID != second.Id) || entry.Upload < int64(len(payload)) || entry.Download < int64(len(payload)) {
			t.Fatalf("unexpected user traffic: %+v", entry)
		}
	}

	if err := server.DelUsers([]panel.UserInfo{first}, tag, info); err != nil {
		t.Fatal(err)
	}
	if _, err := active.Read(echo); err == nil || os.IsTimeout(err) {
		t.Fatalf("revoked user's connection stayed open: %v", err)
	}
	assertDenied(first.Uuid)
	remaining := tcp(second.Uuid)
	defer remaining.Close()
	if err := exchange(remaining); err != nil {
		t.Fatalf("remaining user: %v", err)
	}
	if err := server.DelUsers([]panel.UserInfo{second}, tag, info); err != nil {
		t.Fatal(err)
	}
	assertDenied(second.Uuid)
	assertDenied("")
	addUsers(first)
	restored := tcp(first.Uuid)
	defer restored.Close()
	if err := exchange(restored); err != nil {
		t.Fatalf("restored user: %v", err)
	}
	if err := server.DelNode(tag); err != nil {
		t.Fatal(err)
	}
	for _, inboundTag := range []string{tag, snellShadowTLSTag(tag)} {
		if _, found := server.box.Inbound().Get(inboundTag); found {
			t.Fatalf("inbound %s remained after removing the node", inboundTag)
		}
	}
}

func TestSnellWebsiteSniffPreservesInvalidClientHello(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	// Looks like a TLS handshake record, but the ClientHello is truncated.
	wire := []byte{0x16, 0x03, 0x01, 0, 8, 0x01, 0, 0, 4, 0, 0, 0, 0}
	go func() {
		_, _ = client.Write(wire[:3])
		_, _ = client.Write(wire[3:])
	}()
	prepared, website, err := sniffSnellWebsite(context.Background(), server)
	if err != nil || website {
		t.Fatalf("invalid TLS should be passed to Snell: website=%t, err=%v", website, err)
	}
	_ = client.Close()
	actual, err := io.ReadAll(prepared)
	if err != nil || !bytes.Equal(actual, wire) {
		t.Fatalf("lost bytes after lookahead: %x, %v", actual, err)
	}
}

func startSnellBuiltInWebsite(t *testing.T, sni string) (int, []byte, *http.Client) {
	t.Helper()
	port := freePort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	files := newTestCert(t)
	website, err := decoy.NewServer(decoy.Config{
		ListenAddress:  address,
		DefaultProfile: "web",
		TLS:            &decoy.TLSFiles{CertificateFile: files.CertFile, KeyFile: files.KeyFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- website.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := website.Shutdown(ctx); err != nil {
			t.Errorf("shut down the built-in website: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("serve the built-in website: %v", err)
		}
	})
	cert, err := os.ReadFile(files.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("load the built-in website test certificate")
	}
	oldTLS := &tls.Config{ServerName: sni, RootCAs: roots, MaxVersion: tls.VersionTLS12}
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, oldTLS); err == nil {
		_ = conn.Close()
		t.Fatal("the built-in HTTPS listener accepted TLS 1.2")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{ServerName: sni, RootCAs: roots},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return port, cert, &http.Client{Transport: transport}
}

func TestStaticSnellConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing.json")
	if err := os.WriteFile(path, []byte(`{
		"inbounds": [{"type":"snell","tag":"snell-in","version":6,"psk":"test-shared-key-12345"}],
		"outbounds": [{"type":"snell","tag":"snell-out","server":"127.0.0.1","server_port":8443,"version":6,"psk":"test-shared-key-12345"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := conf.NewSingConfig()
	config.OriginalPath = path
	server, err := New(&conf.CoreConfig{Type: "sing", SingConfig: config})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}
