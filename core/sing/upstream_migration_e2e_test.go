//go:build with_quic && with_utls

package sing

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"github.com/gofrs/uuid/v5"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	hy1 "github.com/sagernet/sing-quic/hysteria"
	hy2 "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
)

type migrationDialer struct{}

func (migrationDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
func (migrationDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
}

// Clients come from the public upstream modules, rather than the server's
// internal compatibility copies. This detects accidental wire-format changes.
func TestUpstreamClientsSurviveUserReindexAndRevoke(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			core := newLifecycleCore(t)
			tag := "upstream-interop-" + protocol
			limiter.AddLimiter(tag, &conf.LimitConfig{}, lifecycleUsers, nil)
			t.Cleanup(func() { limiter.DeleteLimiter(tag) })
			port := freePort(t)
			info := &panel.NodeInfo{Type: protocol, Common: &panel.CommonNode{ServerPort: port}}
			switch protocol {
			case "vmess", "vless":
				info.VAllss = &panel.VAllssNode{Network: "tcp"}
			case "trojan":
				info.Trojan = &panel.TrojanNode{Network: "tcp"}
			case "shadowsocks":
				info.Shadowsocks = &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
			case "hysteria":
				info.Security = panel.Tls
				info.Hysteria = &panel.HysteriaNode{UpMbps: 100, DownMbps: 100}
			case "hysteria2":
				info.Security = panel.Tls
				info.Hysteria2 = &panel.Hysteria2Node{UpMbps: 100, DownMbps: 100}
			case "tuic":
				info.Security = panel.Tls
				info.Tuic = &panel.TuicNode{CongestionControl: "cubic"}
			}
			if err := core.AddNode(tag, info, lifecycleOptions(t, info.Security == panel.Tls)); err != nil {
				t.Fatal(err)
			}
			if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}
			address := fmt.Sprintf("127.0.0.1:%d", port)
			destination := M.ParseSocksaddr(startEchoServer(t))
			user := lifecycleUsers[1].Uuid
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			logger := log.NewNOPFactory().Logger()
			tlsConfig, err := boxTLS.NewSTDClient(ctx, logger, address, option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "n2x.test", ALPN: []string{"h3"}})
			if err != nil {
				t.Fatal(err)
			}
			var dial func() (net.Conn, error)
			var packetDial func() (net.PacketConn, error)
			udpTarget := startMigrationUDPEcho(t)
			switch protocol {
			case "vmess":
				c, err := vmess.NewClient(user, "aes-128-gcm", 0)
				if err != nil {
					t.Fatal(err)
				}
				dial = func() (net.Conn, error) {
					raw, err := net.Dial("tcp", address)
					if err != nil {
						return nil, err
					}
					conn, err := c.DialConn(raw, destination)
					if err != nil {
						raw.Close()
					}
					return conn, err
				}
			case "vless":
				c, err := vless.NewClient(user, "", logger)
				if err != nil {
					t.Fatal(err)
				}
				dial = func() (net.Conn, error) {
					raw, err := net.Dial("tcp", address)
					if err != nil {
						return nil, err
					}
					conn, err := c.DialConn(raw, destination)
					if err != nil {
						raw.Close()
					}
					return conn, err
				}
			case "trojan":
				dial = func() (net.Conn, error) {
					return (trojanMuxDialer{address: address, password: user}).DialContext(ctx, "tcp", destination)
				}
			case "shadowsocks":
				c, err := shadowaead.New("aes-128-gcm", nil, user)
				if err != nil {
					t.Fatal(err)
				}
				dial = func() (net.Conn, error) {
					raw, err := net.Dial("tcp", address)
					if err != nil {
						return nil, err
					}
					conn, err := c.DialConn(raw, destination)
					if err != nil {
						raw.Close()
					}
					return conn, err
				}
			case "hysteria":
				tlsConfig.SetNextProtos(nil)
				c, err := hy1.NewClient(hy1.ClientOptions{Context: ctx, Dialer: migrationDialer{}, Logger: logger, ServerAddress: M.ParseSocksaddr(address), SendBPS: 100000000, ReceiveBPS: 100000000, Password: user, TLSConfig: tlsConfig})
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(nil)
				dial = func() (net.Conn, error) { return c.DialConn(ctx, destination) }
				packetDial = func() (net.PacketConn, error) { return c.ListenPacket(ctx, M.SocksaddrFromNet(udpTarget)) }
			case "hysteria2":
				c, err := hy2.NewClient(hy2.ClientOptions{Context: ctx, Dialer: migrationDialer{}, Logger: logger, ServerAddress: M.ParseSocksaddr(address), Password: user, TLSConfig: tlsConfig})
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(nil)
				dial = func() (net.Conn, error) { return c.DialConn(ctx, destination) }
				packetDial = func() (net.PacketConn, error) { return c.ListenPacket(ctx) }
			case "tuic":
				c, err := tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: migrationDialer{}, ServerAddress: M.ParseSocksaddr(address), UUID: uuid.Must(uuid.FromString(user)), Password: user, TLSConfig: tlsConfig})
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(nil)
				dial = func() (net.Conn, error) { return c.DialConn(ctx, destination) }
				packetDial = func() (net.PacketConn, error) { return c.ListenPacket(ctx) }
			}
			echo := func(conn net.Conn) error {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload := []byte("upstream-user-identity")
				if _, err := conn.Write(payload); err != nil {
					return err
				}
				reply := make([]byte, len(payload))
				_, err := io.ReadFull(conn, reply)
				if err == nil && string(reply) != string(payload) {
					return fmt.Errorf("echo mismatch")
				}
				return err
			}
			conn, err := dial()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := echo(conn); err != nil {
				t.Fatal(err)
			}
			var packets net.PacketConn
			udpEcho := func() error {
				packets.SetReadDeadline(time.Now().Add(time.Second))
				payload := []byte("udp-user-identity")
				if _, err := packets.WriteTo(payload, udpTarget); err != nil {
					return err
				}
				reply := make([]byte, 128)
				n, _, err := packets.ReadFrom(reply)
				if err == nil && string(reply[:n]) != string(payload) {
					return fmt.Errorf("UDP echo mismatch")
				}
				return err
			}
			if packetDial != nil {
				packets, err = packetDial()
				if err != nil {
					t.Fatal(err)
				}
				defer packets.Close()
				if err := udpEcho(); err != nil {
					t.Fatal(err)
				}
			}

			if err := core.DelUsers(lifecycleUsers[:1], tag, info); err != nil {
				t.Fatal(err)
			}
			if err := echo(conn); err != nil {
				t.Fatalf("remaining user lost existing connection: %v", err)
			}
			if packets != nil {
				if err := udpEcho(); err != nil {
					t.Fatalf("remaining UDP user failed: %v", err)
				}
			}
			// Mutate another user's authentication snapshot while new connections arrive.
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			wg.Go(func() {
				for range 8 {
					if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers[:1], NodeInfo: info}); err != nil {
						errs <- err
						return
					}
					if err := core.DelUsers(lifecycleUsers[:1], tag, info); err != nil {
						errs <- err
						return
					}
				}
			})
			for range 2 {
				wg.Go(func() {
					for range 4 {
						c, err := dial()
						if err == nil {
							err = echo(c)
							c.Close()
						}
						if err != nil {
							errs <- err
							return
						}
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			traffic, err := core.GetUserTrafficSlice(tag, false)
			if err != nil {
				t.Fatal(err)
			}
			billed := false
			for _, entry := range traffic {
				if entry.UID != lifecycleUsers[1].Id {
					t.Fatalf("traffic billed to wrong user: %d", entry.UID)
				}
				billed = billed || entry.Upload > 0 && entry.Download > 0
			}
			if !billed {
				t.Fatal("remaining user's traffic was not accounted")
			}
			if err := core.DelUsers(lifecycleUsers[1:], tag, info); err != nil {
				t.Fatal(err)
			}
			if err := echo(conn); err == nil {
				t.Fatal("removed user's existing connection still works")
			}
			if packets != nil {
				if err := udpEcho(); err == nil {
					t.Fatal("removed UDP user still receives traffic")
				}
			}
			stale, err := dial()
			if err == nil {
				defer stale.Close()
				if err := echo(stale); err == nil {
					t.Fatal("stale client session was admitted after removal")
				}
			}
			if err := core.DelNode(tag); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func startMigrationUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], source)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}
