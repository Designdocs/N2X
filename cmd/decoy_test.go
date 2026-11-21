package cmd

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Designdocs/N2X/decoy"
)

func TestResolveDecoyListenAddress(t *testing.T) {
	t.Setenv("N2X_ARTX_DECOY_LISTEN", "127.0.0.1:61000")

	if got := resolveDecoyListen(""); got != "127.0.0.1:61000" {
		t.Fatalf("environment address = %q", got)
	}
	if got := resolveDecoyListen("127.0.0.1:62000"); got != "127.0.0.1:62000" {
		t.Fatalf("flag address = %q", got)
	}
}

func TestDefaultDecoyListen(t *testing.T) {
	t.Setenv("N2X_ARTX_DECOY_LISTEN", "")

	if got := resolveDecoyListen(""); got != "127.0.0.1:60443" {
		t.Fatalf("default address = %q", got)
	}
}

func TestDecoyHTTPSConfigFromEnvironment(t *testing.T) {
	t.Setenv(decoyHTTPSListenEnvironment, "")
	t.Setenv(decoyHTTPSCertEnvironment, "")
	t.Setenv(decoyHTTPSKeyEnvironment, "")
	if config := decoyHTTPSConfig("web"); config != nil {
		t.Fatal("HTTPS should be off without local settings")
	}
	t.Setenv(decoyHTTPSListenEnvironment, "127.0.0.1:50443")
	if config := decoyHTTPSConfig("web"); config == nil || config.ListenAddress != "127.0.0.1:50443" || config.TLS.GetCertificate == nil {
		t.Fatalf("HTTPS listen address alone should use managed certificates: %+v", config)
	}
	t.Setenv(decoyHTTPSListenEnvironment, "")
	t.Setenv(decoyHTTPSCertEnvironment, "/etc/N2X/ssl/fullchain.pem")
	t.Setenv(decoyHTTPSKeyEnvironment, "/etc/N2X/ssl/privkey.pem")
	config := decoyHTTPSConfig("web")
	if config == nil || config.ListenAddress != "127.0.0.1:50443" || config.DefaultProfile != "web" ||
		config.TLS.CertificateFile != "/etc/N2X/ssl/fullchain.pem" || config.TLS.KeyFile != "/etc/N2X/ssl/privkey.pem" || config.TLS.GetCertificate != nil {
		t.Fatalf("unexpected companion HTTPS settings: %+v", config)
	}
	t.Setenv(decoyHTTPSListenEnvironment, "127.0.0.1:8443")
	if config := decoyHTTPSConfig("web"); config == nil || config.ListenAddress != "127.0.0.1:8443" {
		t.Fatalf("explicit companion HTTPS address was lost: %+v", config)
	}
}

func TestDecoyKeepsHTTPAvailableWhenHTTPSFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runDecoyServer(ctx, address, "web", &decoy.Config{TLS: &decoy.TLSFiles{}})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("companion HTTP server: %v", err)
		}
	})
	client := &http.Client{Timeout: 500 * time.Millisecond}
	defer client.CloseIdleConnections()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		resp, err := client.Head("http://" + address)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("companion HTTP status = %d, want 200", resp.StatusCode)
			}
			return
		}
	}
	t.Fatal("companion HTTP listener did not start with unusable HTTPS settings")
}
