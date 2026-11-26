//go:build with_utls

package xray

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Designdocs/N2X/api/panel"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/gorilla/websocket"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type anyTLSWireClient interface {
	CreateProxy(context.Context, M.Socksaddr) (net.Conn, error)
	Close() error
}

func TestXrayAnyTLSRealClientHTTPSAndReconnect(t *testing.T) {
	for _, security := range []int{panel.Tls, panel.Reality} {
		t.Run(fmt.Sprintf("security=%d", security), func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("N2X_WS_SCAN_STATE_DIR", dir)
			f := newProtocolFixtureWithGuard(t, &panel.NodeInfo{Type: "anytls", Security: security, AnyTls: &panel.AnyTlsNode{Tls: security}}, true)
			entry := startScanTestRelay(t, f)
			if security == panel.Tls {
				checkSensitiveEntry(t, f, entry, true)
				// AnyTLS has no WS path. An unrelated upgrade must not enter the audit.
				d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: f.roots}, HandshakeTimeout: 3 * time.Second}
				ws, response, err := d.Dial("wss://"+entry+"/ws", nil)
				if ws != nil {
					ws.Close()
				}
				if response != nil {
					response.Body.Close()
				}
				if err == nil || (response != nil && response.StatusCode == 404) {
					t.Fatal("AnyTLS applied the WS path rule")
				}

			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			dialTLS := func(ctx context.Context) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", entry)
				if err != nil {
					return nil, err
				}
				raw.SetDeadline(time.Now().Add(15 * time.Second))
				if security == panel.Tls {
					conn := tls.Client(raw, &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
					if err = conn.HandshakeContext(ctx); err != nil {
						raw.Close()
						return nil, err
					}
					return conn, nil
				}
				config, err := boxTLS.NewRealityClient(ctx, log.NewNOPFactory().Logger(), f.address, option.OutboundTLSOptions{Enabled: true, ServerName: "n2x.test", UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: f.publicKey, ShortID: "0123456789abcdef"}})
				if err != nil {
					raw.Close()
					return nil, err
				}
				conn, err := boxTLS.ClientHandshake(ctx, raw, config)
				if err != nil {
					raw.Close()
				}
				return conn, err
			}
			newClient := func(password string) anyTLSWireClient {
				c, err := createAnyTLSWireClient(ctx, password, dialTLS)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				return c
			}
			client := newClient(f.users[0].Uuid)
			// A request for the same path sent through an authenticated tunnel is user data.
			echoAddress := startTCPEcho(t)
			tunnel, err := client.CreateProxy(ctx, M.ParseSocksaddr(echoAddress))
			if err != nil {
				t.Fatal(err)
			}
			tunnel.SetDeadline(time.Now().Add(5 * time.Second))
			payload := "GET /.git/config HTTP/1.1\r\nHost: " + echoAddress + "\r\n\r\n"
			if _, err = io.WriteString(tunnel, payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(tunnel, got); err != nil || string(got) != payload {
				t.Fatalf("tunnel payload changed: %v", err)
			}
			tunnel.Close()
			if security == panel.Tls {
				data, err := os.ReadFile(filepath.Join(dir, "intercepts.jsonl"))
				if err != nil || strings.Count(string(data), "\n") != 1 {
					t.Fatalf("unexpected tunnel audit: %v %s", err, data)
				}
			}

			transfer := func(c anyTLSWireClient) error {
				conn, err := c.CreateProxy(ctx, M.ParseSocksaddr(f.target))
				if err != nil {
					return err
				}
				return f.https(ctx, conn)
			}
			if err := transfer(client); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for range 4 {
				wg.Go(func() { errs <- transfer(client) })
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			f.checkTraffic(t, 101, int64(len(f.payload)*5))
			client.Close()
			if err := transfer(newClient(f.users[0].Uuid)); err != nil {
				t.Fatalf("fresh-session reconnect: %v", err)
			}
			reject := func(c anyTLSWireClient) {
				t.Helper()
				conn, err := c.CreateProxy(ctx, M.ParseSocksaddr(startTCPEcho(t)))
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.WriteString(conn, "unauthorized"); err != nil {
					return
				}
				buf := make([]byte, len("unauthorized"))
				if _, err = io.ReadFull(conn, buf); err == nil {
					t.Fatal("unauthorized user transferred data")
				}
			}
			reject(newClient("wrong-password"))
			if err := f.core.DelUsers(f.users[:1], f.tag, f.info); err != nil {
				t.Fatal(err)
			}
			f.waitUsers(t, 1)
			reject(newClient(f.users[0].Uuid))
			if err := transfer(newClient(f.users[1].Uuid)); err != nil {
				t.Fatalf("remaining user: %v", err)
			}
			if _, err := f.core.AddUsers(&vCore.AddUsersParams{Tag: f.tag, NodeInfo: f.info, Users: f.users[:1]}); err != nil {
				t.Fatal(err)
			}
			f.waitUsers(t, 2)
			if err := transfer(newClient(f.users[0].Uuid)); err != nil {
				t.Fatalf("restored user: %v", err)
			}
		})
	}
}
