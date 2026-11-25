//go:build sing

package node

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/core/sing"
	"github.com/Designdocs/N2X/limiter"
)

func TestSnellTakesOverReleasedWebsitePort(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "external") }))
	defer server.Close()
	pair := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := validDNSCertConfig(t)
	cfg.CertMode = "file"
	if err := os.WriteFile(cfg.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	origin := panel.SnellWebsiteFallback{ServerName: server.Certificate().DNSNames[0], ServerPort: uint16(server.Listener.Addr().(*net.TCPAddr).Port)}
	public, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := public.Addr().String()
	port := public.Addr().(*net.TCPAddr).Port
	public.Close()
	body := fmt.Sprintf(`{"server_port":%d,"version":6,"psk":"test-shared-key","website_fallback":{"server_name":%q,"server_port":%d},"base_config":{"push_interval":60,"pull_interval":60}}`, port, origin.ServerName, origin.ServerPort)
	panelServer := fakePanel(t, &body, `{"users":[]}`)
	api, err := panel.New(&conf.ApiConfig{APIHost: panelServer.URL, Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	core, err := sing.New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	limiter.Init()
	c := NewController(core, api, &conf.Options{ListenIP: "127.0.0.1", CertConfig: cfg, SingOptions: conf.NewSingOptions()}, nil)
	c.websites.roots = roots
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: origin.ServerName}}}
	read := func() (string, error) {
		resp, err := client.Get("https://" + address + "/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || !resp.TLS.PeerCertificates[0].Equal(server.Certificate()) {
			return "", fmt.Errorf("wrong response or certificate")
		}
		page, err := io.ReadAll(resp.Body)
		return string(page), err
	}
	time.Sleep(snellWebsiteRetryInterval + 100*time.Millisecond)
	if page, err := read(); err != nil || page != "external" {
		t.Fatalf("external listener interrupted: %q %v", page, err)
	}
	server.Close()
	released := time.Now()
	deadline := time.Now().Add(3 * snellWebsiteRetryInterval)
	for time.Now().Before(deadline) {
		if page, err := read(); err == nil && strings.Contains(page, "<title>") {
			t.Logf("Snell entry served the built-in page and original certificate %v after release", time.Since(released))
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("built-in HTTPS did not take over the released port")
}
