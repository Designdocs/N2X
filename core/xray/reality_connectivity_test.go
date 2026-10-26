//go:build with_utls && !race

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
	"encoding/json"
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
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
)

// Exercise the deployed N2X Xray path with an independently implemented client.
// The public Vision client uses uintptr TLS field access and needs a non-race
// wire test; the N2X/Core race suites remain enabled separately.
func TestXrayVLESSRealityVisionPublicClient(t *testing.T) {
	initLimiterOnce.Do(limiter.Init)
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
	httpsPayload := bytes.Repeat([]byte("REALITY-Vision-inner-TLS"), 16384)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(httpsPayload) }))
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	origin.StartTLS()
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	for _, tc := range []struct {
		client, flow          string
		https, invalidShortID bool
	}{
		{"sing", "", false, false}, {"sing", "xtls-rprx-vision", false, false}, {"xray", "xtls-rprx-vision", false, false},
		{"sing", "xtls-rprx-vision", true, false}, {"xray", "xtls-rprx-vision", true, false},
		{"xray-legacy-fingerprint", "xtls-rprx-vision", true, false},
		{"sing", "xtls-rprx-vision", false, true},
	} {
		flow := tc.flow
		name := tc.client + "/flow=" + flow
		if tc.https {
			name += "/https"
		}
		if tc.invalidShortID {
			name += "/invalid-short-id"
		}
		t.Run(name, func(t *testing.T) {
			outbounds := filepath.Join(t.TempDir(), "outbound.json")
			// A loopback echo target is permitted explicitly for this isolated fixture.
			if err := os.WriteFile(outbounds, []byte(`[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow"}]}}]`), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := conf.NewXrayConfig()
			cfg.LogConfig.Level = "debug"
			cfg.OutboundConfigPath = outbounds
			instance, err := New(&conf.CoreConfig{XrayConfig: cfg})
			if err != nil {
				t.Fatal(err)
			}
			server := instance.(*Xray)
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			nodePort := freeLoopbackPort(t)
			tag := "xray-reality-wire-" + flow
			info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, Common: &panel.CommonNode{ServerPort: nodePort}, VAllss: &panel.VAllssNode{Network: "tcp", Flow: flow, Tls: panel.Reality, TlsSettings: panel.TlsSettings{ServerName: "n2x.test", Dest: host, ServerPort: port, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortId: "0123456789abcdef"}}}
			options := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
			if err := server.AddNode(tag, info, options); err != nil {
				t.Fatal(err)
			}
			users := []panel.UserInfo{{Id: 1, Uuid: singMuxTestPassword}}
			limiter.AddLimiter(tag, &conf.LimitConfig{}, users, nil)
			defer limiter.DeleteLimiter(tag)
			if _, err := server.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(nodePort))
			waitForListener(t, address)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			target := startTCPEcho(t)
			if tc.https {
				target = origin.Listener.Addr().String()
			}
			pubkey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			var conn net.Conn
			if tc.client == "xray" || tc.client == "xray-legacy-fingerprint" {
				fingerprint := "chrome"
				if tc.client == "xray-legacy-fingerprint" {
					fingerprint = "hellochrome_120"
				}
				conn = dialXrayRealityClient(t, ctx, address, target, pubkey, flow, fingerprint)
			} else {
				shortID := "0123456789abcdef"
				if tc.invalidShortID {
					shortID = "fedcba9876543210"
				}
				tlsConfig, err := boxTLS.NewRealityClient(ctx, log.NewNOPFactory().Logger(), address, option.OutboundTLSOptions{Enabled: true, ServerName: "n2x.test", UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: pubkey, ShortID: shortID}})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				// Upstream post-handshake record probing can wait one five-second
				// interval on the first connection to a previously unseen decoy.
				raw.SetDeadline(time.Now().Add(15 * time.Second))
				secure, err := boxTLS.ClientHandshake(ctx, raw, tlsConfig)
				if tc.invalidShortID {
					if err == nil {
						secure.Close()
						t.Fatal("REALITY accepted an invalid short ID")
					}
					return
				}
				if err != nil {
					t.Fatalf("REALITY handshake: %v", err)
				}
				client, err := vless.NewClient(singMuxTestPassword, flow, log.NewNOPFactory().Logger())
				if err != nil {
					t.Fatal(err)
				}
				conn, err = client.DialConn(secure, M.ParseSocksaddr(target))
				if err != nil {
					t.Fatalf("VLESS handshake: %v", err)
				}
			}
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			defer conn.Close()
			if tc.https {
				innerTLS := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
				defer innerTLS.Close()
				if err := innerTLS.HandshakeContext(ctx); err != nil {
					t.Fatalf("proxied HTTPS handshake: %v", err)
				}
				if _, err := io.WriteString(innerTLS, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(innerTLS), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusOK || !bytes.Equal(body, httpsPayload) {
					t.Fatal("HTTPS response mismatch")
				}
				return
			}
			payload := bytes.Repeat([]byte("VLESS-REALITY-Vision"), 4096)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatalf("proxy transfer: %v", err)
			}
			if !bytes.Equal(reply, payload) {
				t.Fatal("echo mismatch")
			}
		})
	}
}

// Use the upstream Xray client implementation as well as the independent sing
// client, so compatibility must preserve the modern hybrid ClientHello path.
func dialXrayRealityClient(t *testing.T, ctx context.Context, address, target, publicKey, flow, fingerprint string) net.Conn {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]any{"vnext": []any{map[string]any{
		"address": host, "port": port, "users": []any{map[string]any{"id": singMuxTestPassword, "encryption": "none", "flow": flow}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	protocol := xconf.TransportProtocol("tcp")
	config, err := (&xconf.Config{OutboundConfigs: []xconf.OutboundDetourConfig{{
		Protocol: "vless", Settings: (*json.RawMessage)(&settings), StreamSetting: &xconf.StreamConfig{
			Network: &protocol, Security: "reality", REALITYSettings: &xconf.REALITYConfig{
				ServerName: "n2x.test", Fingerprint: fingerprint, PublicKey: publicKey, ShortId: "0123456789abcdef",
			},
		},
	}}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	client, err := xcore.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	dest, err := xnet.ParseDestination("tcp:" + target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := xcore.Dial(ctx, client, dest)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
