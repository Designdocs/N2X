//go:build with_utls

package sing

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRealityMigrationRealHandshakes(t *testing.T) {
	runRealityHandshakes(t, []string{"vless", "trojan", "anytls"}, false)
}
func runRealityHandshakes(t *testing.T, protocols []string, vision bool) {
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	decoy.EnableHTTP2 = true
	decoy.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	decoy.StartTLS()
	defer decoy.Close()
	host, port, err := net.SplitHostPort(decoy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	settings := panel.TlsSettings{ServerName: "n2x.test", Dest: host, ServerPort: port, ShortId: "0123456789abcdef", PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes())}
	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			core := newLifecycleCore(t)
			tag := "reality-migration-" + protocol
			user := lifecycleUsers[0]
			limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
			t.Cleanup(func() { limiter.DeleteLimiter(tag) })
			nodePort := freePort(t)
			info := &panel.NodeInfo{Type: protocol, Security: panel.Reality, Common: &panel.CommonNode{ServerPort: nodePort}}
			switch protocol {
			case "vless":
				info.VAllss = &panel.VAllssNode{Network: "tcp", Tls: panel.Reality, TlsSettings: settings}
			case "trojan":
				info.Trojan = &panel.TrojanNode{Network: "tcp", Tls: panel.Reality, TlsSettings: settings}
			case "anytls":
				info.AnyTls = &panel.AnyTlsNode{Tls: panel.Reality, TlsSettings: settings}
			}
			if vision && protocol == "vless" {
				info.VAllss.Flow = "xtls-rprx-vision"
			}
			if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
				t.Fatal(err)
			}
			if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(nodePort))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			config, err := boxTLS.NewRealityClient(core.ctx, log.NewNOPFactory().Logger(), address, option.OutboundTLSOptions{Enabled: true, ServerName: settings.ServerName, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: settings.ShortId}})
			if err != nil {
				t.Fatal(err)
			}
			dialTLS := func(ctx context.Context) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					return nil, err
				}
				conn, err := boxTLS.ClientHandshake(ctx, raw, config)
				if err != nil {
					raw.Close()
				}
				return conn, err
			}
			target := M.ParseSocksaddr(startEchoServer(t))
			var conn net.Conn
			switch protocol {
			case "vless":
				raw, e := dialTLS(ctx)
				if e != nil {
					t.Fatal(e)
				}
				client, e := vless.NewClient(user.Uuid, info.VAllss.Flow, log.NewNOPFactory().Logger())
				if e != nil {
					t.Fatal(e)
				}
				conn, err = client.DialConn(raw, target)
			case "trojan":
				conn, err = dialTLS(ctx)
				if err == nil {
					sum := sha256.Sum224([]byte(user.Uuid))
					var header bytes.Buffer
					header.WriteString(hex.EncodeToString(sum[:]))
					header.WriteString("\r\n")
					header.WriteByte(1)
					err = M.SocksaddrSerializer.WriteAddrPort(&header, target)
					header.WriteString("\r\n")
					if err == nil {
						_, err = conn.Write(header.Bytes())
					}
				}
			case "anytls":
				client, e := anytls.NewClient(ctx, anytls.ClientConfig{Password: user.Uuid, Logger: log.NewNOPFactory().Logger(), DialOut: dialTLS, IdleSessionCheckInterval: time.Second, IdleSessionTimeout: time.Second})
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				conn, err = client.CreateProxy(ctx, target)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte(fmt.Sprintf("reality-%s", protocol))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, reply) {
				t.Fatal("REALITY echo mismatch")
			}
		})
	}
}

func TestMigrationNodeRemovalClosesPendingTCPHandshakes(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			core := newLifecycleCore(t)
			port := freePort(t)
			tag := "pending-" + protocol
			info := &panel.NodeInfo{Type: protocol, Common: &panel.CommonNode{ServerPort: port}}
			switch protocol {
			case "vmess", "vless":
				info.VAllss = &panel.VAllssNode{Network: "tcp"}
			case "trojan":
				info.Trojan = &panel.TrojanNode{Network: "tcp"}
			case "shadowsocks":
				info.Shadowsocks = &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
			}
			if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := core.DelNode(tag); err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			_, err = conn.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("pending handshake survived removal")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("pending handshake was not closed", err)
			}
		})
	}
}

type migrationMetadataTracker struct {
	adapter.ConnectionTracker
	result chan adapter.InboundContext
}

func (r *migrationMetadataTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	r.result <- metadata
	return conn
}

func TestMigrationPreservesPerNodeSniffAndDomainStrategy(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "sniff-compat"
	user := lifecycleUsers[0]
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	tracker := &migrationMetadataTracker{result: make(chan adapter.InboundContext, 1)}
	core.router.AppendTracker(tracker)
	port := freePort(t)
	info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "tcp"}}
	options := lifecycleOptions(t, false)
	options.SingOptions.SniffEnabled = true
	options.SingOptions.SniffOverrideDestination = true
	options.SingOptions.DomainStrategy = "ipv4_only"
	if err := core.AddNode(tag, info, options); err != nil {
		t.Fatal(err)
	}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("sniff-body")) }))
	defer target.Close()
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	client, err := vless.NewClient(user.Uuid, "", log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	destination := M.SocksaddrFromNet(target.Listener.Addr())
	conn, err := client.DialConn(raw, destination)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", destination.Port)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reply, []byte("sniff-body")) {
		t.Fatal("sniff lost buffered request")
	}
	select {
	case metadata := <-tracker.result:
		if metadata.Protocol != "http" || metadata.Domain != "localhost" || metadata.Destination.Fqdn != "localhost" {
			t.Fatalf("sniff/override lost: protocol=%s domain=%s destination=%s", metadata.Protocol, metadata.Domain, metadata.Destination)
		}
		if len(metadata.DestinationAddresses) == 0 {
			t.Fatal("domain strategy was ignored")
		}
		for _, address := range metadata.DestinationAddresses {
			if !address.Is4() {
				t.Fatal("ipv4_only returned a non-IPv4 address")
			}
		}
	case <-time.After(time.Second):
		t.Fatal("routing metadata was not reported")
	}
}
