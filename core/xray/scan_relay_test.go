//go:build with_utls

package xray

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// All probes and the authenticated client use this one L4 entry and backend.
// The relay only copies bytes in both directions.
func startScanTestRelay(t *testing.T, f *protocolFixture) string {
	t.Helper()
	front, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	go func() {
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, err := net.DialTimeout("tcp4", f.address, 3*time.Second)
				if err != nil {
					return
				}
				defer b.Close()
				go func() { io.Copy(b, c); b.(*net.TCPConn).CloseWrite() }()
				io.Copy(c, b)
			}()
		}
	}()
	return front.Addr().String()
}

func exercisePlainRelay(t *testing.T, f *protocolFixture) string {
	t.Helper()
	entry := startScanTestRelay(t, f)
	tc := &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1"}
	tr := &http.Transport{TLSClientConfig: tc}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	get := func(path string, want int) {
		t.Helper()
		resp, err := client.Get("https://" + entry + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: got %d, want %d", path, resp.StatusCode, want)
		}
	}
	get("/.git/config?private=omit", 404)
	dialer := websocket.Dialer{TLSClientConfig: tc, HandshakeTimeout: 4 * time.Second}
	conn, resp, err := dialer.Dial("wss://"+entry+"/other-ws", nil)
	if conn != nil {
		conn.Close()
	}
	if resp == nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unexpected WS response: %d", resp.StatusCode)
	}
	if f.info.VAllss.Network != "httpupgrade" {
		get("/ws", 200)
		get("/", 200)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("N2X_WS_SCAN_STATE_DIR"), "intercepts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || strings.Contains(string(data), "private=omit") {
		t.Fatalf("unexpected log %s", data)
	}
	for i, line := range lines {
		var event struct{ Path, Node string }
		if err := json.Unmarshal([]byte(line), &event); err != nil || event.Node != f.tag || event.Path != []string{"/.git/config", "/other-ws"}[i] {
			t.Fatal(line)
		}
	}
	t.Log("plain TCP relay: sensitive request and wrong WS handshake each returned 404 and produced one interception record")
	return entry
}

func checkSensitiveEntry(t *testing.T, f *protocolFixture, entry string, secure bool) {
	t.Helper()
	scheme := "http"
	if secure {
		scheme = "https"
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get(scheme + "://" + entry + "/.git/config")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	data, err := os.ReadFile(filepath.Join(os.Getenv("N2X_WS_SCAN_STATE_DIR"), "intercepts.jsonl"))
	if resp.StatusCode != 404 || err != nil || !strings.Contains(string(data), "/.git/config") {
		t.Fatalf("sensitive request: %d %s %v", resp.StatusCode, data, err)
	}
}
