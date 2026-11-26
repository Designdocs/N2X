//go:build with_utls

package xray

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/Designdocs/N2X/conf"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	M "github.com/sagernet/sing/common/metadata"
)

func ddnsRelayFixture(t *testing.T, info *panel.NodeInfo) (*protocolFixture, string, string) {
	t.Helper()
	peer := os.Getenv("N2X_TEST_DDNS_PEER")
	if peer == "" {
		t.Skip("requires DDNS Master forwarding test binary")
	}
	dir := t.TempDir()
	t.Setenv("N2X_WS_SCAN_STATE_DIR", dir)
	cmd := exec.Command(peer, "-test.run=^TestN2XRelayPeer$")
	cmd.Env = append(os.Environ(), "N2X_TEST_RELAY_DIR="+dir)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	lines := bufio.NewScanner(out)
	read := func(prefix string) string {
		for lines.Scan() {
			if strings.HasPrefix(lines.Text(), prefix) {
				return strings.TrimPrefix(lines.Text(), prefix)
			}
			t.Log(lines.Text())
		}
		t.Fatalf("missing %s", prefix)
		return ""
	}
	read("CA-READY")
	f := newProtocolFixtureWithCA(t, info, true, filepath.Join(dir, "master-public.pem"), "::1")
	fmt.Fprintln(in, f.address)
	entry := read("ENTRY ")
	return f, entry, dir
}

type countingLanding struct {
	net.Listener
	accepts *atomic.Int64
}

func (l countingLanding) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}

func TestAuthenticatedDDNSRelay(t *testing.T) {
	var accepted atomic.Int64
	previous := wrapScanListener
	wrapScanListener = func(tag string, cfg conf.WSScanGuardConfig, l net.Listener) (net.Listener, error) {
		return previous(tag, cfg, countingLanding{l, &accepted})
	}
	t.Cleanup(func() { wrapScanListener = previous })
	f, entry, dir := ddnsRelayFixture(t, &panel.NodeInfo{Type: "anytls", Security: panel.Tls, AnyTls: &panel.AnyTlsNode{Tls: panel.Tls}})
	scanner := net.ParseIP("127.0.0.1")
	normal := secondVisitorIP()
	valid := func(src net.IP, uid int) error { return visitAnyTLS(f, entry, src, uid) }
	for idx, ip := range []net.IP{scanner, normal} {
		if err := valid(ip, idx); err != nil {
			t.Fatalf("baseline user %d: %v", idx, err)
		}
	}
	scan := func(dst string) { scanSensitive(t, f, dst) }
	scan(f.address)
	scan(entry)
	logPath := filepath.Join(dir, "intercepts.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil || strings.Count(string(data), `"visitor":"127.0.0.1"`) != 3 {
		t.Fatalf("expected 3 verified, 3 unverified: %s %v", data, err)
	}
	if err := valid(scanner, 0); err != nil {
		t.Fatalf("one round banned visitor: %v", err)
	}
	waitScanRound(t)
	scan(entry)
	before := accepted.Load()
	if err := valid(scanner, 0); err == nil {
		t.Fatal("scanner authenticated after ban")
	}
	if after := accepted.Load(); after != before {
		t.Fatalf("scanner reconnect reached landing: %d -> %d", before, after)
	}
	t.Logf("scanner reconnect: landing TCP accepts %d -> %d", before, accepted.Load())
	if err := valid(normal, 1); err != nil {
		t.Fatalf("shared relay normal user lost connectivity: %v", err)
	}
	if accepted.Load() <= before {
		t.Fatal("positive control: normal client missed landing counter")
	}
	t.Logf("normal user: landing TCP accepts %d -> %d; full HTTPS payload verified", before, accepted.Load())
	scan(f.address)
	data, _ = os.ReadFile(logPath)
	if strings.Count(string(data), `"action":"node-ban"`) != 1 {
		t.Fatalf("unexpected bans: %s", data)
	}
	t.Log("same DDNS TCP relay: both AnyTLS users transferred HTTPS; only the verified scanner lost access after two rounds; normal user reconnected and transferred HTTPS")
}

func TestAuthenticatedDDNSWrongWS(t *testing.T) {
	f, entry, dir := ddnsRelayFixture(t, &panel.NodeInfo{Type: "vless", Security: panel.Tls, VAllss: &panel.VAllssNode{Tls: panel.Tls, Network: "ws", NetworkSettings: json.RawMessage(`{"path":"/configured"}`)}})
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1"}, HandshakeTimeout: 5 * time.Second}
	for _, p := range []string{"/ws", "/other", "/third"} {
		c, resp, _ := d.Dial("wss://"+entry+p, http.Header{"X-Forwarded-For": []string{"192.0.2.99"}})
		if c != nil {
			c.Close()
		}
		if resp == nil || resp.StatusCode != 404 {
			t.Fatalf("wrong handshake %s", p)
		}
		resp.Body.Close()
	}
	data, err := os.ReadFile(filepath.Join(dir, "intercepts.jsonl"))
	if err != nil || strings.Count(string(data), `"visitor":"127.0.0.1"`) != 3 || strings.Contains(string(data), "192.0.2.99") {
		t.Fatalf("unverified WS identity: %s %v", data, err)
	}
	t.Log("wrong WS upgrades attributed to the verified TCP visitor; supplied forwarding header ignored")
}

func secondVisitorIP() net.IP {
	var normal net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok && p.IP.To4() != nil && !p.IP.IsLoopback() {
			normal = p.IP
			break
		}
	}
	if normal == nil {
		normal = net.ParseIP("127.0.0.2")
	}
	return normal
}
func visitAnyTLS(f *protocolFixture, entry string, src net.IP, uid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{LocalAddr: &net.TCPAddr{IP: src}}, Config: &tls.Config{ServerName: "127.0.0.1", RootCAs: f.roots}}
	client, err := createAnyTLSWireClient(ctx, f.users[uid].Uuid, func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", entry) })
	if err != nil {
		return err
	}
	defer client.Close()
	c, err := client.CreateProxy(ctx, M.ParseSocksaddr(f.target))
	if err != nil {
		return err
	}
	return f.https(ctx, c)
}
func scanSensitive(t *testing.T, f *protocolFixture, dst string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "127.0.0.1", RootCAs: f.roots}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, p := range []string{"/.git/config", "/.env", "/wp-admin/"} {
		r, err := c.Get("https://" + dst + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatal(r.StatusCode)
		}
	}
}
func waitScanRound(t *testing.T) {
	t.Helper()
	delay := 10*time.Minute + time.Second
	if s := os.Getenv("N2X_TEST_ROUND_DELAY"); s != "" {
		var err error
		delay, err = time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(delay)
}

func TestExplicitDirectNodeBan(t *testing.T) {
	if os.Getenv("N2X_TEST_DDNS_PEER") == "" {
		t.Skip("extended scan-guard wire tests")
	}
	t.Setenv("N2X_WS_SCAN_STATE_DIR", t.TempDir())
	f := newProtocolFixtureWithIngress(t, &panel.NodeInfo{Type: "anytls", Security: panel.Tls, AnyTls: &panel.AnyTlsNode{Tls: panel.Tls}}, true, "", "127.0.0.1", true)
	scanner := net.ParseIP("127.0.0.1")
	if err := visitAnyTLS(f, f.address, scanner, 0); err != nil {
		t.Fatal(err)
	}
	scanSensitive(t, f, f.address)
	waitScanRound(t)
	scanSensitive(t, f, f.address)
	if err := visitAnyTLS(f, f.address, scanner, 0); err == nil {
		t.Fatal("confirmed direct scanner connected")
	}
	if err := visitAnyTLS(f, f.address, secondVisitorIP(), 1); err != nil {
		t.Fatal(err)
	}
	t.Log("explicit direct-only node: scanner denied, normal visitor reconnected and transferred HTTPS")
}
