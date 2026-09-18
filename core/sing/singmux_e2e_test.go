package sing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	mux "github.com/sagernet/sing-mux"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// trojanMuxDialer opens one plain trojan connection per mux session, aimed
// at sing-mux's magic destination the way mihomo and sing-box clients do.
type trojanMuxDialer struct {
	address  string
	password string
}

func (d trojanMuxDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
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

func (trojanMuxDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("trojan test dialer carries no packets")
}

var _ N.Dialer = trojanMuxDialer{}

func startEchoServer(t *testing.T) string {
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

func startMuxTrojanNode(t *testing.T, tag string, multiplex *panel.MultiplexSettings) (*Sing, string) {
	t.Helper()
	core := newLifecycleCore(t)
	user := lifecycleUsers[0]
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	port := freePort(t)
	info := &panel.NodeInfo{
		Type:   "trojan",
		Common: &panel.CommonNode{ServerPort: port, Multiplex: multiplex},
		Trojan: &panel.TrojanNode{Network: "tcp"},
	}
	if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatalf("AddUsers: %v", err)
	}
	return core, fmt.Sprintf("127.0.0.1:%d", port)
}

func muxEcho(ctx context.Context, client *mux.Client, target string, payload []byte) error {
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

func newTrojanMuxClient(t *testing.T, address string, padding bool) *mux.Client {
	t.Helper()
	client, err := mux.NewClient(mux.Options{
		Dialer:         trojanMuxDialer{address: address, password: lifecycleUsers[0].Uuid},
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

// The panel switch alone turns sing-mux on: nothing in the local config asks
// for it, yet clients handed an smux block must get through, and every
// stream is still billed to the user.
func TestSingTrojanServesMuxWhenPanelEnablesMultiplex(t *testing.T) {
	for _, padding := range []bool{false, true} {
		t.Run(fmt.Sprintf("padding=%v", padding), func(t *testing.T) {
			tag := fmt.Sprintf("sing-mux-on-%v", padding)
			core, address := startMuxTrojanNode(t, tag, &panel.MultiplexSettings{Enabled: true, Padding: padding})
			client := newTrojanMuxClient(t, address, padding)
			echo := startEchoServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- muxEcho(ctx, client, echo, bytes.Repeat([]byte{byte('a' + i)}, 32*1024))
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("TCP stream over sing-mux: %v", err)
				}
			}

			want := int64(4 * 32 * 1024)
			var up, down int64
			for deadline := time.Now().Add(3 * time.Second); ; {
				traffic, err := core.GetUserTrafficSlice(tag, true)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range traffic {
					up += entry.Upload
					down += entry.Download
				}
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

func TestSingTrojanRefusesMuxWhenPanelLeavesMultiplexOff(t *testing.T) {
	_, address := startMuxTrojanNode(t, "sing-mux-off", nil)
	client := newTrojanMuxClient(t, address, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := muxEcho(ctx, client, startEchoServer(t), []byte("ping")); err == nil {
		t.Fatal("a node without the panel switch served a sing-mux session")
	}
}

func TestBuildMultiplexFollowsPanel(t *testing.T) {
	on := &panel.NodeInfo{Common: &panel.CommonNode{Multiplex: &panel.MultiplexSettings{Enabled: true, Padding: true}}}
	off := &panel.NodeInfo{Common: &panel.CommonNode{}}
	localOn := testOptions()
	localOn.SingOptions.Multiplex = &conf.MultiplexConfig{Enabled: true, Brutal: conf.BrutalOptions{Enabled: true, UpMbps: 100, DownMbps: 100}}
	localOff := testOptions()
	localOff.SingOptions.Multiplex = nil

	if got := buildMultiplex(off, localOff); got != nil {
		t.Fatalf("panel off, no local config: %+v, want nil", got)
	}
	if got := buildMultiplex(on, localOff); got == nil || !got.Enabled || !got.Padding || got.Brutal != nil {
		t.Fatalf("panel on: %+v, want enabled with the panel's padding and no brutal", got)
	}
	if got := buildMultiplex(off, localOn); got == nil || !got.Enabled || got.Padding || !got.Brutal.Enabled {
		t.Fatalf("local only: %+v, want the local config unchanged", got)
	}
	if got := buildMultiplex(on, localOn); got == nil || !got.Enabled || !got.Padding || !got.Brutal.Enabled {
		t.Fatalf("both: %+v, want the panel's padding with the local brutal", got)
	}
}
