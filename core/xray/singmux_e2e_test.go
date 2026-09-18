package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	mux "github.com/sagernet/sing-mux"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const singMuxTestPassword = "5f0c1b9e-0d6a-4a53-9c43-8f1f2c0e7a11"

var initLimiterOnce sync.Once

// trojanDialer opens one trojan connection per mux session, aimed at
// sing-mux's magic destination the way mihomo and sing-box do.
type trojanDialer struct {
	address  string
	password string
}

func (d trojanDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum224([]byte(d.password))
	var header bytes.Buffer
	header.WriteString(hex.EncodeToString(sum[:]))
	header.WriteString("\r\n")
	header.WriteByte(0x01) // CONNECT
	header.WriteByte(0x03) // domain
	header.WriteByte(byte(len(destination.Fqdn)))
	header.WriteString(destination.Fqdn)
	header.WriteByte(byte(destination.Port >> 8))
	header.WriteByte(byte(destination.Port))
	header.WriteString("\r\n")
	if _, err := conn.Write(header.Bytes()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (trojanDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("trojan test dialer carries no packets")
}

var _ N.Dialer = trojanDialer{}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := packetConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = packetConn.WriteTo(buffer[:n], from)
		}
	}()
	return packetConn.LocalAddr().String()
}

// startTrojanNode brings up the real N2X core with one trojan node the way
// the controller does: node, limiter, then users.
func startTrojanNode(t *testing.T, tag string, multiplex *panel.MultiplexSettings, speedLimit int) (*Xray, string) {
	t.Helper()
	initLimiterOnce.Do(limiter.Init)
	// The stock config carries no outbound; streams need somewhere to go.
	outbounds := filepath.Join(t.TempDir(), "outbound.json")
	if err := os.WriteFile(outbounds, []byte(`[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow"}]}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	xrayConfig := conf.NewXrayConfig()
	xrayConfig.OutboundConfigPath = outbounds
	instance, err := New(&conf.CoreConfig{XrayConfig: xrayConfig})
	if err != nil {
		t.Fatal(err)
	}
	x := instance.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })

	port := freeLoopbackPort(t)
	info := &panel.NodeInfo{
		Type:   "trojan",
		Common: &panel.CommonNode{ServerPort: port, Multiplex: multiplex},
		Trojan: &panel.TrojanNode{Network: "tcp"},
	}
	options := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	if err := x.AddNode(tag, info, options); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	users := []panel.UserInfo{{Id: 1, Uuid: singMuxTestPassword, SpeedLimit: speedLimit}}
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	waitForListener(t, address)
	return x, address
}

func newSingMuxClient(t *testing.T, nodeAddress string, padding bool) *mux.Client {
	t.Helper()
	client, err := mux.NewClient(mux.Options{
		Dialer:         trojanDialer{address: nodeAddress, password: singMuxTestPassword},
		Protocol:       "yamux",
		MaxConnections: 1,
		Padding:        padding,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func echoOverStream(ctx context.Context, client *mux.Client, target string, payload []byte) error {
	conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !bytes.Equal(reply, payload) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func TestTrojanNodeServesSingMuxWhenPanelEnablesMultiplex(t *testing.T) {
	// A speed limit makes every stream rewrite its inbound's splice state,
	// which streams sharing one inbound would race on.
	for _, tc := range []struct {
		padding    bool
		speedLimit int
	}{{false, 0}, {true, 0}, {false, 1000}} {
		padding := tc.padding
		t.Run(fmt.Sprintf("padding=%v,speed=%d", padding, tc.speedLimit), func(t *testing.T) {
			tag := fmt.Sprintf("singmux-on-%v-%d", padding, tc.speedLimit)
			x, nodeAddress := startTrojanNode(t, tag, &panel.MultiplexSettings{Enabled: true, Padding: padding}, tc.speedLimit)
			client := newSingMuxClient(t, nodeAddress, padding)
			tcpEcho := startTCPEcho(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			// Several streams at once over the one trojan connection.
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					payload := bytes.Repeat([]byte{byte('a' + i)}, 32*1024)
					errs <- echoOverStream(ctx, client, tcpEcho, payload)
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("TCP stream over sing-mux: %v", err)
				}
			}

			udpEcho := startUDPEcho(t)
			packetConn, err := client.ListenPacket(ctx, M.ParseSocksaddr(udpEcho))
			if err != nil {
				t.Fatalf("ListenPacket() error = %v", err)
			}
			defer packetConn.Close()
			_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
			target := M.ParseSocksaddr(udpEcho).UDPAddr()
			for _, message := range []string{"first datagram", "second datagram"} {
				if _, err := packetConn.WriteTo([]byte(message), target); err != nil {
					t.Fatalf("WriteTo() error = %v", err)
				}
				reply := make([]byte, 1024)
				n, _, err := packetConn.ReadFrom(reply)
				if err != nil {
					t.Fatalf("UDP over sing-mux: %v", err)
				}
				if string(reply[:n]) != message {
					t.Fatalf("UDP echo = %q, want %q", reply[:n], message)
				}
			}

			// Streams are dispatched one by one, so each is billed to the user.
			// Counters are bumped after the write the client already read, so
			// give the last few a moment to land.
			want := int64(8 * 32 * 1024)
			var up, down int64
			for deadline := time.Now().Add(3 * time.Second); ; {
				up, down = userTraffic(t, x, tag, up, down)
				if (up >= want && down >= want) || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if up < want || down < want {
				t.Fatalf("traffic up=%d down=%d, want both >= %d", up, down, want)
			}
		})
	}
}

// userTraffic drains the counters and adds them to what was seen so far.
func userTraffic(t *testing.T, x *Xray, tag string, up, down int64) (int64, int64) {
	t.Helper()
	traffic, err := x.GetUserTrafficSlice(tag, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range traffic {
		up += entry.Upload
		down += entry.Download
	}
	return up, down
}

func TestTrojanNodeRefusesSingMuxWhenPanelLeavesMultiplexOff(t *testing.T) {
	_, nodeAddress := startTrojanNode(t, "singmux-off", nil, 0)
	client := newSingMuxClient(t, nodeAddress, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := echoOverStream(ctx, client, startTCPEcho(t), []byte("ping")); err == nil {
		t.Fatal("a node without the panel switch served a sing-mux session")
	}
}
