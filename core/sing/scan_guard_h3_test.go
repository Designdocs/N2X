//go:build with_quic

package sing

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/quic-go/http3"
)

func TestHysteria2SensitiveWebsite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("N2X_WS_SCAN_STATE_DIR", dir)
	core := newLifecycleCore(t)
	core.scanConfig = conf.WSScanGuardConfig{Enabled: true, LogMaxMB: 10}
	opts := lifecycleOptions(t, true)
	info := testNode("hysteria2", panel.Tls)
	info.Common.ServerPort = freePort(t)
	info.Hysteria2 = &panel.Hysteria2Node{}
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
	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "n2x.test", RootCAs: roots}}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/.env", info.Common.ServerPort))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	data, err := os.ReadFile(filepath.Join(dir, "intercepts.jsonl"))
	if resp.ProtoMajor != 3 || resp.StatusCode != 404 || err != nil || !strings.Contains(string(data), "/.env") {
		t.Fatalf("HTTP/3 rejection: %d %s %v", resp.StatusCode, data, err)
	}
}
