package node

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

const (
	redirectTestHost = "114514.gay"
	redirectCertFile = "../test_data/1.pem"
	redirectKeyFile  = "../test_data/1.key"
)

func TestHTTPSRedirectManagerRedirectsTrustedHost(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig())
	if err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}

	response := redirectRequest(
		t,
		manager.Address(),
		redirectTestHost,
		redirectTestHost,
		"/docs/a%2Fb?source=test&next=%2Faccount%3Ftab%3D1",
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusMovedPermanently)
	}
	if location := response.Header.Get("Location"); location != "https://"+redirectTestHost+":8443/docs/a%2Fb?source=test&next=%2Faccount%3Ftab%3D1" {
		t.Fatalf("Location = %q", location)
	}
}

func TestHTTPSRedirectManagerDoesNothingForPublicPort443(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	invalidCertConfig := &conf.CertConfig{
		CertMode: "file",
		CertFile: "/missing/cert.pem",
		KeyFile:  "/missing/key.pem",
	}
	if err := manager.Upsert("artx-test", redirectNodeInfo(443), invalidCertConfig); err != nil {
		t.Fatalf("register public-port-443 node: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q, want no listener", address)
	}
}

func TestHTTPSRedirectManagerBlocksForExistingPublicPort443Node(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("redirected", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected redirect listener to start")
	}

	manager.Prepare("artx-443", redirectNodeInfo(443))
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q while an ArtX node owns public port 443", address)
	}

	if err := manager.Remove("artx-443"); err != nil {
		t.Fatalf("remove public-port-443 blocker: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected pending HTTPS redirect to resume")
	}
}

func TestHTTPSRedirectManagerStopsWhenNodeChangesToPublicPort443(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected redirect listener to start")
	}

	if err := manager.Upsert("artx-test", redirectNodeInfo(443), redirectCertConfig()); err != nil {
		t.Fatalf("disable HTTPS redirect: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q after public port changed to 443", address)
	}
}

func TestHTTPSRedirectManagerUpdatesPublicPort(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register initial HTTPS redirect: %v", err)
	}
	if err := manager.Upsert("artx-test", redirectNodeInfo(9443), redirectCertConfig()); err != nil {
		t.Fatalf("update HTTPS redirect: %v", err)
	}

	response := redirectRequest(t, manager.Address(), redirectTestHost, redirectTestHost, "/account?tab=usage")
	defer response.Body.Close()

	if location := response.Header.Get("Location"); location != "https://"+redirectTestHost+":9443/account?tab=usage" {
		t.Fatalf("Location = %q", location)
	}
}

func TestHTTPSRedirectManagerDoesNotShareArtXListenerPort443(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	nodeInfo := redirectNodeInfo(8443)
	nodeInfo.Common.ServerPort = 443
	if err := manager.Upsert("artx-test", nodeInfo, redirectCertConfig()); err == nil {
		t.Fatal("redirect unexpectedly shared port 443 with the ArtX listener")
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q, want no redirect listener", address)
	}
}

func TestHTTPSRedirectManagerStopsForAnyProtocolListenerPort443(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected redirect listener to start")
	}

	if err := manager.Upsert("vless-443", protocolNodeInfo("vless", 443), nil); err != nil {
		t.Fatalf("register cross-protocol port-443 blocker: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q while another protocol owns port 443", address)
	}

	if err := manager.Upsert("vless-443", protocolNodeInfo("vless", 8443), nil); err != nil {
		t.Fatalf("move cross-protocol listener away from port 443: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected pending HTTPS redirect to resume")
	}
}

func TestHTTPSRedirectManagerRemainsBlockedUntilLastProtocolLeavesPort443(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("trojan-443", protocolNodeInfo("trojan", 443), nil); err != nil {
		t.Fatalf("register first cross-protocol blocker: %v", err)
	}
	if err := manager.Upsert("vless-443", protocolNodeInfo("vless", 443), nil); err != nil {
		t.Fatalf("register second cross-protocol blocker: %v", err)
	}
	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register pending HTTPS redirect: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q with two port-443 blockers", address)
	}

	if err := manager.Upsert("trojan-443", protocolNodeInfo("trojan", 8443), nil); err != nil {
		t.Fatalf("remove first cross-protocol blocker: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q while one port-443 blocker remains", address)
	}

	if err := manager.Upsert("vless-443", protocolNodeInfo("vless", 8443), nil); err != nil {
		t.Fatalf("remove final cross-protocol blocker: %v", err)
	}
	if manager.Address() == "" {
		t.Fatal("expected pending HTTPS redirect after final blocker left port 443")
	}
}

func TestHTTPSRedirectManagerRejectsUnknownHost(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}

	response := redirectRequest(t, manager.Address(), redirectTestHost, "unknown.example.com", "/")
	defer response.Body.Close()

	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusMisdirectedRequest)
	}
	if location := response.Header.Get("Location"); location != "" {
		t.Fatalf("unexpected Location for unknown host: %q", location)
	}
}

func TestHTTPSRedirectManagerRejectsUnknownSNI(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err != nil {
		t.Fatalf("register HTTPS redirect: %v", err)
	}

	client := redirectHTTPClient("unknown.example.com")
	request, err := http.NewRequest(http.MethodGet, "https://"+manager.Address()+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Host = redirectTestHost
	if _, err = client.Do(request); err == nil {
		t.Fatal("unknown SNI unexpectedly completed a TLS request")
	}
}

func TestHTTPSRedirectManagerReportsOccupiedListenAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listen address: %v", err)
	}
	defer listener.Close()

	manager := newHTTPSRedirectManager(listener.Addr().String())
	t.Cleanup(func() { _ = manager.Close() })

	if err = manager.Upsert("artx-test", redirectNodeInfo(8443), redirectCertConfig()); err == nil {
		t.Fatal("occupied redirect address unexpectedly succeeded")
	}
}

func TestHTTPSRedirectManagerIgnoresIncompletePublicEndpoint(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	t.Cleanup(func() { _ = manager.Close() })

	nodeInfo := redirectNodeInfo(0)
	nodeInfo.ArtX.PublicHost = ""
	if err := manager.Upsert("artx-test", nodeInfo, redirectCertConfig()); err != nil {
		t.Fatalf("ignore incomplete endpoint: %v", err)
	}
	if address := manager.Address(); address != "" {
		t.Fatalf("listener address = %q, want no listener", address)
	}
}

func protocolNodeInfo(protocol string, serverPort int) *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:   protocol,
		Common: &panel.CommonNode{ServerPort: serverPort},
	}
}

func redirectNodeInfo(publicPort int) *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:   "artx",
		Common: &panel.CommonNode{ServerPort: publicPort},
		ArtX: &panel.ArtXNode{
			PublicHost: redirectTestHost,
			PublicPort: publicPort,
		},
	}
}

func redirectCertConfig() *conf.CertConfig {
	return &conf.CertConfig{
		CertMode: "file",
		CertFile: redirectCertFile,
		KeyFile:  redirectKeyFile,
	}
}

func redirectRequest(
	t *testing.T,
	address string,
	serverName string,
	host string,
	requestURI string,
) *http.Response {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, "https://"+address+requestURI, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Host = host

	response, err := redirectHTTPClient(serverName).Do(request)
	if err != nil {
		t.Fatalf("perform HTTPS redirect request: %v", err)
	}
	return response
}

func redirectHTTPClient(serverName string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
}

func TestHTTPSRedirectManagerCloseIsIdempotent(t *testing.T) {
	manager := newHTTPSRedirectManager("127.0.0.1:0")
	if err := manager.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := manager.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("second close: %v", err)
	}
}
