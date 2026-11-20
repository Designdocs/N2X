package sing

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

func TestManagedSnellV6(t *testing.T) {
	const tag = "snell-v6"
	const psk = "test-shared-key-12345"
	server := newLifecycleCore(t)
	first, second := lifecycleUsers[0], lifecycleUsers[1]
	limiter.AddLimiter(tag, &conf.LimitConfig{}, lifecycleUsers, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	common := &panel.CommonNode{ServerPort: freePort(t)}
	info := &panel.NodeInfo{
		Type: "snell", Common: common,
		Snell: &panel.SnellNode{CommonNode: *common, Version: panel.SnellVersion, PSK: psk},
	}
	if err := server.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", common.ServerPort)
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
	dial := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
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
