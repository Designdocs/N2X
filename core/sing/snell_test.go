package sing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

func TestManagedSnellV6(t *testing.T) {
	t.Run("direct", func(t *testing.T) { testManagedSnellV6(t, false) })
	t.Run("shadowtls", func(t *testing.T) { testManagedSnellV6(t, true) })
}

func testManagedSnellV6(t *testing.T, wrapped bool) {
	tag := t.Name()
	const psk = "test-shared-key-12345"
	const outerKey = "test-shadowtls-key"
	server := newLifecycleCore(t)
	first, second := lifecycleUsers[0], lifecycleUsers[1]
	limiter.AddLimiter(tag, &conf.LimitConfig{}, lifecycleUsers, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	common := &panel.CommonNode{ServerPort: freePort(t)}
	info := &panel.NodeInfo{
		Type: "snell", Common: common,
		Snell: &panel.SnellNode{CommonNode: *common, Version: panel.SnellVersion, PSK: psk},
	}
	var cover *httptest.Server
	if wrapped {
		cover = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "local handshake server")
		}))
		cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		cover.StartTLS()
		t.Cleanup(cover.Close)
		info.Snell.ShadowTLS = &panel.SnellShadowTLS{
			Password: outerKey,
			Handshake: panel.ShadowTLSHandshake{
				Server:     "localhost",
				ServerPort: cover.Listener.Addr().(*net.TCPAddr).Port,
			},
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
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cover.Certificate().Raw})
		outerClient = func(password string) *shadowtls.Outbound {
			t.Helper()
			client, err := shadowtls.NewOutbound(server.ctx, server.router, log.NewNOPFactory().Logger(), "shadowtls-client",
				option.ShadowTLSOutboundOptions{
					Version:       3,
					Password:      password,
					ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(common.ServerPort)},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
						Enabled: true, ServerName: "example.com", MinVersion: "1.3", Certificate: []string{string(cert)},
					}},
				})
			if err != nil {
				t.Fatal(err)
			}
			return client.(*shadowtls.Outbound)
		}
		httpClient := cover.Client()
		httpClient.Timeout = 3 * time.Second
		resp, err := httpClient.Get("https://" + address)
		if err != nil {
			t.Fatalf("ordinary TLS request: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "local handshake server" {
			t.Fatalf("ordinary TLS request did not reach the configured target: %q (%v)", body, err)
		}
	}
	destination := M.ParseSocksaddr(startEchoServer(t))
	payload := []byte("snell echo")
	newClient := func(key string) *snellv6.Client {
		t.Helper()
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), UserKey: []byte(key)})
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
