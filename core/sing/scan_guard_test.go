package sing

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"

	"github.com/Designdocs/N2X/conf"
)

func TestSingRelayScanGuard(t *testing.T) {
	t.Setenv("N2X_WS_SCAN_STATE_DIR", t.TempDir())
	core := newLifecycleCore(t)
	core.scanConfig = conf.WSScanGuardConfig{Enabled: true, LogMaxMB: 10}
	for _, transport := range []string{"ws", "httpupgrade"} {
		t.Run(transport, func(t *testing.T) {
			tag := t.Name()
			port := freePort(t)
			info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: transport, NetworkSettings: json.RawMessage(`{"path":"/private"}`)}}
			if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
				t.Fatal(err)
			}
			defer core.DelNode(tag)
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.env", port))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatal(resp.StatusCode)
			}
			log, err := os.ReadFile(filepath.Join(os.Getenv("N2X_WS_SCAN_STATE_DIR"), "intercepts.jsonl"))
			if err != nil || !strings.Contains(string(log), tag) {
				t.Fatalf("missing interception: %v", err)
			}
		})
	}
}

func TestSingNativeSensitiveRequest(t *testing.T) {
	for _, protocol := range []string{"anytls", "vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("N2X_WS_SCAN_STATE_DIR", dir)
			core := newLifecycleCore(t)
			core.scanConfig = conf.WSScanGuardConfig{Enabled: true, LogMaxMB: 10}
			opts := lifecycleOptions(t, true)
			info := &panel.NodeInfo{Type: protocol, Security: panel.Tls, Common: &panel.CommonNode{ServerPort: freePort(t)}, AnyTls: &panel.AnyTlsNode{}, VAllss: &panel.VAllssNode{Tls: panel.Tls, Network: "tcp"}, Trojan: &panel.TrojanNode{Tls: panel.Tls, Network: "tcp"}}
			if err := core.AddNode(t.Name(), info, opts); err != nil {
				t.Fatal(err)
			}
			defer core.DelNode(t.Name())
			cert, err := os.ReadFile(opts.CertConfig.CertFile)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(cert)
			tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "n2x.test", RootCAs: roots}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/.git/config", info.Common.ServerPort))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			data, err := os.ReadFile(filepath.Join(dir, "intercepts.jsonl"))
			if resp.StatusCode != 404 || err != nil || !strings.Contains(string(data), "/.git/config") {
				t.Fatalf("scan: %d %s %v", resp.StatusCode, data, err)
			}
		})
	}
}
