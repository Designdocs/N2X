package sing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

// TestMain initialises the limiter registry. cmd/server.go does this before
// any node starts; without it AddLimiter writes to a nil map.
func TestMain(m *testing.M) {
	limiter.Init()
	os.Exit(m.Run())
}

// newTestCert writes a throwaway self-signed certificate and returns a
// CertConfig pointing at it. Protocols such as naive refuse to start without
// a usable certificate, so the lifecycle tests need a real one on disk.
func newTestCert(t *testing.T) *conf.CertConfig {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "n2x.test"},
		DNSNames:     []string{"n2x.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return &conf.CertConfig{CertMode: "file", CertFile: certPath, KeyFile: keyPath}
}

// freePort reserves a port by binding and releasing it. There is an inherent
// race, but it keeps parallel test runs from colliding on a fixed port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a local port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return port
}

// newLifecycleCore boots a real sing-box instance for the lifecycle tests.
func newLifecycleCore(t *testing.T) *Sing {
	t.Helper()
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	core := c.(*Sing)
	if err := core.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := core.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return core
}

func lifecycleOptions(t *testing.T, withCert bool) *conf.Options {
	t.Helper()
	o := &conf.Options{ListenIP: "127.0.0.1", CertConfig: &conf.CertConfig{CertMode: "none"}}
	if withCert {
		o.CertConfig = newTestCert(t)
	}
	o.SingOptions = conf.NewSingOptions()
	return o
}

var lifecycleUsers = []panel.UserInfo{
	{Id: 101, Uuid: "11111111-1111-1111-1111-111111111111"},
	{Id: 102, Uuid: "22222222-2222-2222-2222-222222222222"},
}

// TestAnyTLSLifecycle walks a node through the full sequence the node
// controller drives: add node, add users, remove a user, remove the node.
func TestAnyTLSLifecycle(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "anytls-lifecycle"
	limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	info := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: freePort(t)},
		AnyTls:   &panel.AnyTlsNode{},
	}
	if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if _, found := core.box.Inbound().Get(tag); !found {
		t.Fatal("inbound was not created")
	}

	added, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info})
	if err != nil {
		t.Fatalf("AddUsers: %v", err)
	}
	if added != len(lifecycleUsers) {
		t.Fatalf("added = %d, want %d", added, len(lifecycleUsers))
	}

	if err := core.DelUsers(lifecycleUsers[:1], tag, info); err != nil {
		t.Fatalf("DelUsers: %v", err)
	}
	if err := core.DelNode(tag); err != nil {
		t.Fatalf("DelNode: %v", err)
	}
	if _, found := core.box.Inbound().Get(tag); found {
		t.Fatal("inbound outlived the node")
	}
}

// TestShadowTLSLifecycle checks the two-inbound composition: both inbounds
// must exist, users must land on the Shadowsocks detour, the detour must map
// back to the node tag, and DelNode must take both down.
func TestShadowTLSLifecycle(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "shadowtls-lifecycle"
	limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	info := &panel.NodeInfo{
		Type:     "shadowtls",
		Security: panel.None,
		Common:   &panel.CommonNode{ServerPort: freePort(t)},
		ShadowTLS: &panel.ShadowTLSNode{
			Version:   3,
			Password:  "node-password",
			Handshake: panel.ShadowTLSHandshake{Server: "www.microsoft.com", ServerPort: 443},
			Cipher:    "2022-blake3-aes-128-gcm",
			ServerKey: "8JCsPssfgS8tiRwiMlhARg==",
		},
	}
	if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	for _, want := range []string{tag, detourTag(tag)} {
		if _, found := core.box.Inbound().Get(want); !found {
			t.Fatalf("inbound %q was not created", want)
		}
	}
	// Traffic arrives tagged with the detour; it must be attributed to the node.
	if got := core.resolveNodeTag(detourTag(tag)); got != tag {
		t.Fatalf("resolveNodeTag(detour) = %q, want %q", got, tag)
	}

	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info}); err != nil {
		t.Fatalf("AddUsers: %v", err)
	}
	if err := core.DelUsers(lifecycleUsers[:1], tag, info); err != nil {
		t.Fatalf("DelUsers: %v", err)
	}

	if err := core.DelNode(tag); err != nil {
		t.Fatalf("DelNode: %v", err)
	}
	for _, gone := range []string{tag, detourTag(tag)} {
		if _, found := core.box.Inbound().Get(gone); found {
			t.Fatalf("inbound %q outlived the node", gone)
		}
	}
}

// TestNaiveLifecycle covers the rebuild-based user management: no listener
// until the first user, a listener afterwards, and no listener once the last
// user is gone.
func TestNaiveLifecycle(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "naive-lifecycle"
	limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	info := &panel.NodeInfo{
		Type:     "naive",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: freePort(t)},
		Naive:    &panel.NaiveNode{Network: "tcp"},
	}
	if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	// Naive cannot start without users, so AddNode must not create one yet.
	if _, found := core.box.Inbound().Get(tag); found {
		t.Fatal("naive inbound was created before any user existed")
	}

	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info}); err != nil {
		t.Fatalf("AddUsers: %v", err)
	}
	if _, found := core.box.Inbound().Get(tag); !found {
		t.Fatal("naive inbound was not created after the first users arrived")
	}

	// Removing one of two users keeps the listener up.
	if err := core.DelUsers(lifecycleUsers[:1], tag, info); err != nil {
		t.Fatalf("DelUsers: %v", err)
	}
	if _, found := core.box.Inbound().Get(tag); !found {
		t.Fatal("naive inbound disappeared while a user remained")
	}

	// Removing the last user closes the port rather than serving nobody.
	if err := core.DelUsers(lifecycleUsers[1:], tag, info); err != nil {
		t.Fatalf("DelUsers: %v", err)
	}
	if _, found := core.box.Inbound().Get(tag); found {
		t.Fatal("naive inbound stayed up with no users")
	}

	if err := core.DelNode(tag); err != nil {
		t.Fatalf("DelNode: %v", err)
	}
}

// TestAddNodeRejectsBadSettingsWithoutLeakingState makes sure a failed
// AddNode does not leave the node registered.
func TestAddNodeRejectsBadSettingsWithoutLeakingState(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "broken"

	info := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: freePort(t)},
		// AnyTls settings deliberately absent.
	}
	if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err == nil {
		t.Fatal("AddNode should fail when the node settings are missing")
	}
	if _, ok := core.nodeTypes.Load(tag); ok {
		t.Fatal("a failed AddNode left the node type registered")
	}
	if got := core.reportMinTraffic(tag); got != 0 {
		t.Fatalf("a failed AddNode left a reporting threshold: %d", got)
	}
}
