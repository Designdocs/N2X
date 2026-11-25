package node

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"

	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

// startStubCore accepts every node removal and fails every node addition
// with addErr.
type startStubCore struct {
	vCore.Core
	addErr error
}

func (c *startStubCore) AddNode(string, *panel.NodeInfo, *conf.Options) error { return c.addErr }

func (c *startStubCore) DelNode(string) error { return nil }

func (c *startStubCore) AddUsers(p *vCore.AddUsersParams) (int, error) {
	return len(p.Users), nil
}

// fakePanel serves a node with the supplied config and user roster.
// A nil nodeBody answers the config request with 404.
func fakePanel(t *testing.T, nodeBody *string, roster string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if nodeBody == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(*nodeBody))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(roster))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func nodeBody(fields string) *string {
	body := `{"server_port": 443, "base_config": {"push_interval": 60, "pull_interval": 60}, ` + fields + `}`
	return &body
}

func TestNodeStartReportsWhichStageFailed(t *testing.T) {
	limiter.Init()
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name     string
		nodeType string
		nodeBody *string
		addErr   error
		want     StartStage
		wantText string
	}{
		{
			name:     "panel unreachable",
			nodeType: "anytls",
			nodeBody: nil,
			want:     StagePanel,
			wantText: "get node info error",
		},
		{
			name:     "panel-only certificate is refused",
			nodeType: "anytls",
			nodeBody: nodeBody(`"server_name": "edge.example.com", "cert_config": {"cert_mode": "file", "cert_file": "` +
				missing + `.pem", "key_file": "` + missing + `.key"}`),
			want:     StageCert,
			wantText: "requires a local CertConfig",
		},
		{
			name:     "core rejects the node",
			nodeType: "shadowsocks",
			nodeBody: nodeBody(`"cipher": "aes-128-gcm"`),
			addErr:   errors.New("inbound build failed"),
			want:     StageCore,
			wantText: "inbound build failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			panelServer := fakePanel(t, tt.nodeBody, `{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}`)
			nodes := []conf.NodeConfig{
				{ApiConfig: conf.ApiConfig{APIHost: panelServer.URL, Key: "token", NodeType: tt.nodeType, NodeID: 7}},
			}
			n := New()
			failures, err := n.Start(nodes, &startStubCore{addErr: tt.addErr})
			defer n.Close()
			if err != nil {
				t.Fatalf("Start returned %v, want per-node failures only", err)
			}
			if len(failures) != 1 {
				t.Fatalf("failures = %+v, want exactly one", failures)
			}
			got := failures[0]
			if got.Index != 0 || got.Stage != tt.want {
				t.Errorf("failure = {Index:%d Stage:%q}, want {Index:0 Stage:%q}", got.Index, got.Stage, tt.want)
			}
			if got.Err == nil || !strings.Contains(got.Err.Error(), tt.wantText) {
				t.Errorf("failure error = %v, want it to mention %q", got.Err, tt.wantText)
			}
		})
	}
}

func TestSnellStartsWithEmptyRoster(t *testing.T) {
	limiter.Init()
	server := fakePanel(t, nodeBody(`"version":6,"psk":"test-shared-key"`), `{"users":[]}`)
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	controller := NewController(&startStubCore{}, client, &conf.Options{}, nil)
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
}

func TestSnellModeReloadRetriesAfterRosterFailure(t *testing.T) {
	var changing, failRoster atomic.Bool
	defaultConfig := *nodeBody(`"version":6,"psk":"test-shared-key"`)
	unshapedConfig := *nodeBody(`"version":6,"psk":"test-shared-key","mode":"unshaped"`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			body := defaultConfig
			if changing.Load() {
				body = unshapedConfig
			}
			_, _ = w.Write([]byte(body))
		case "/api/v1/server/UniProxy/user":
			if failRoster.Load() {
				_, _ = w.Write([]byte(`{"users":"invalid"}`))
				return
			}
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	controller := NewController(&startStubCore{}, client, &conf.Options{}, nil)
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })

	changing.Store(true)
	failRoster.Store(true)
	if err := controller.nodeInfoMonitor(); err != nil || controller.info.Snell.Mode != panel.SnellModeDefault {
		t.Fatalf("failed fetch should keep the previous mode: mode=%s err=%v", controller.info.Snell.Mode, err)
	}
	failRoster.Store(false)
	if err := controller.nodeInfoMonitor(); err != nil || controller.info.Snell.Mode != panel.SnellModeUnshaped {
		t.Fatalf("next pull should retry the mode: mode=%s err=%v", controller.info.Snell.Mode, err)
	}
}

func TestSnellWebsiteFallbackKeepsActiveNodeIfOriginIsInvalid(t *testing.T) {
	limiter.Init()
	website := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(website.Close)
	port := website.Listener.Addr().(*net.TCPAddr).Port
	const original = `"version":6,"psk":"test-shared-key","shadowtls":{"password":"test-outer-key","handshake":{"server":"cover.example.com"}}`
	configs := []string{
		original,
		fmt.Sprintf(`"version":6,"psk":"test-shared-key","shadowtls":{"password":"test-outer-key","handshake":{"server":"127.0.0.1","server_port":%d},"fallback_server_name":"cover.example.com"}`, port),
		fmt.Sprintf(`"version":6,"psk":"test-shared-key","website_fallback":{"server_name":"cover.example.com","server_port":%d}`, port),
	}
	var selected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			_, _ = w.Write([]byte(*nodeBody(configs[selected.Load()])))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	controller := NewController(&startStubCore{}, client, &conf.Options{ListenIP: "0.0.0.0"}, nil)
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	current := controller.info
	for i, name := range []string{"ShadowTLS", "direct"} {
		t.Run(name, func(t *testing.T) {
			selected.Store(int32(i + 1))
			if err := controller.nodeInfoMonitor(); err != nil || controller.info != current {
				t.Fatalf("a non-TLS website origin should keep the running Snell node: err=%v", err)
			}
		})
	}
}

func TestSnellDirectFallbackCertificateLifecycle(t *testing.T) {
	limiter.Init()
	cfg := validDNSCertConfig(t)
	orders := stubCertIssuance(t, nil, nil)
	// Simulate an issuer returning a short-lived certificate so the first
	// scheduled expiry check also exercises the renewal path.
	roots := x509.NewCertPool()
	issueCert = func(*conf.CertConfig) error {
		*orders++
		leaf, key := writeTestCertificate(t, cfg.CertFile, time.Now().Add(10*24*time.Hour))
		roots.AddCert(leaf)
		return os.WriteFile(cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	}
	renewed := make(chan struct{}, 1)
	oldRenew := renewIssuedCert
	renewIssuedCert = func(*conf.CertConfig) error { renewed <- struct{}{}; return nil }
	t.Cleanup(func() { renewIssuedCert = oldRenew })

	const direct = `"version":6,"psk":"test-shared-key"`
	freePort := func() uint16 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return uint16(l.Addr().(*net.TCPAddr).Port)
	}
	fallback := func(port uint16) string {
		return direct + fmt.Sprintf(`,"website_fallback":{"server_name":"us.example.com","server_port":%d}`, port)
	}
	first := freePort()

	body := nodeBody(fallback(first))
	server := fakePanel(t, body, `{"users":[]}`)
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "token", NodeType: "snell", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	controller := NewController(&startStubCore{}, client, &conf.Options{CertConfig: cfg}, nil)
	controller.websites.roots = roots
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	select {
	case <-renewed:
	case <-time.After(5 * time.Second):
		t.Fatal("fallback certificate did not renew")
	}
	task := controller.renewCertPeriodic
	if *orders != 1 || task == nil || task.Interval != 24*time.Hour {
		t.Fatal("expected initial issuance and daily renewal")
	}
	readPage := func(origin panel.SnellWebsiteFallback) {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: origin.ServerName},
		}}
		resp, err := client.Get("https://" + origin.Address() + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		page, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 || len(page) == 0 {
			t.Fatal("missing HTTPS page")
		}
	}
	original := controller.websiteOrigin
	readPage(original)
	// A second node on this port must survive the first node's port change.
	second := panel.SnellWebsiteFallback{ServerName: "second.example.com", ServerPort: first}
	shared, err := controller.websites.acquire(second, cfg)
	if err != nil || shared == nil {
		t.Fatalf("share: %v", err)
	}
	defer func() {
		if shared != nil {
			shared.release()
		}
	}()
	readPage(second)
	newPort := freePort()
	*body = *nodeBody(fallback(newPort))
	core := controller.server.(*startStubCore)
	core.addErr = errors.New("temporary listener failure")
	if err := controller.nodeInfoMonitor(); err != nil || controller.websiteOrigin != original {
		t.Fatalf("premature listener switch: %v", err)
	}
	readPage(original)
	core.addErr = nil
	if err := controller.nodeInfoMonitor(); err != nil || controller.websiteOrigin.ServerPort != newPort {
		t.Fatalf("port switch: %v", err)
	}
	readPage(controller.websiteOrigin)
	readPage(second)
	shared.release()
	shared = nil
	if conn, err := net.DialTimeout("tcp", original.Address(), time.Second); err == nil {
		conn.Close()
		t.Fatal("unused port still listening")
	}
	*body = *nodeBody(direct)
	if err := controller.nodeInfoMonitor(); err != nil || controller.renewCertPeriodic != nil {
		t.Fatalf("disabling fallback must stop renewals: %v", err)
	}
	if err := task.Execute(); err != nil || len(renewed) != 0 {
		t.Fatal("disabled fallback still renewed")
	}
	if err := os.Remove(cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	*body = *nodeBody(fallback(first))
	issueCert = func(*conf.CertConfig) error { *orders++; return errors.New("ACME unavailable") }
	if err := controller.nodeInfoMonitor(); err != nil || *orders != 2 ||
		controller.info.Snell.WebsiteFallback != nil || controller.renewCertPeriodic != nil {
		t.Fatal("failed hot-enable must attempt issuance and preserve direct mode")
	}
}

func TestSnellReusesExistingHTTPSListener(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "external") }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := &Controller{Options: &conf.Options{ListenIP: "0.0.0.0"}, websites: &snellWebsites{roots: roots}}
	origin := panel.SnellWebsiteFallback{ServerName: server.Certificate().DNSNames[0], ServerPort: uint16(server.Listener.Addr().(*net.TCPAddr).Port)}
	next := &panel.NodeInfo{Snell: &panel.SnellNode{WebsiteFallback: &origin}}
	next.Common = &panel.CommonNode{ServerPort: 8443}
	change, err := c.prepareSnellWebsite(next)
	if err != nil {
		t.Fatal(err)
	}
	if change.lease == nil || c.websites.ports[origin.Address()].server != nil {
		t.Fatal("external listener incorrectly owned")
	}
	change.apply(c)
	off, err := c.prepareSnellWebsite(&panel.NodeInfo{})
	if err != nil {
		t.Fatal(err)
	}
	off.apply(c)
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	if err != nil || string(page) != "external" {
		t.Fatal("external listener was changed")
	}
}

type rosterStubCore struct {
	vCore.Core
	deleted []panel.UserInfo
}

func (c *rosterStubCore) DelUsers(users []panel.UserInfo, _ string, _ *panel.NodeInfo) error {
	c.deleted = append(c.deleted, users...)
	return nil
}

func TestInvalidNodeConfigStillRevokesRemovedUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			_, _ = w.Write([]byte(`{"server_port":443,"routes":[{"action":"dns","match":[]}]}`))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "dummy", NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	core := &rosterStubCore{}
	controller := NewController(core, client, &conf.Options{}, nil)
	controller.tag = t.Name()
	controller.info = &panel.NodeInfo{Type: "vless"}
	controller.userList = []panel.UserInfo{{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001"}}
	controller.limiter = limiter.AddLimiter(controller.tag, &conf.LimitConfig{}, controller.userList, nil)
	controller.limiterRef.Store(controller.limiter)
	defer limiter.DeleteLimiter(controller.tag)
	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if len(core.deleted) != 1 || len(controller.userList) != 0 {
		t.Fatalf("invalid node config blocked credential revocation: deleted=%d", len(core.deleted))
	}
}
