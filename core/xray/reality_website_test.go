//go:build with_utls && !race

package xray

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"github.com/pires/go-proxyproto"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestRealityWebsiteSameListener(t *testing.T) {
	const siteName = "us-pro-uc.nom-loc.com"
	const realityName = "www.analog.com"
	const flow = "xtls-rprx-vision"
	decoy := httptest.NewUnstartedServer(http.NotFoundHandler())
	decoy.EnableHTTP2 = true
	decoy.StartTLS()
	defer decoy.Close()
	host, port, err := net.SplitHostPort(decoy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, child := websiteTestCertificate(t, siteName)
	if !child {
		return
	}

	for _, tc := range []struct {
		name                     string
		siteProxy, upstreamProxy bool
	}{
		{"plain_https_origin", false, false},
		{"website_client_ip", true, false},
		{"upstream_client_ip", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "%s %s %s", r.TLS.ServerName, r.URL.Path, r.RemoteAddr)
			}))
			sitePort := site.Listener.Addr().(*net.TCPAddr).Port
			if tc.siteProxy {
				site.Listener = &proxyproto.Listener{Listener: site.Listener, ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }}
			}
			site.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			site.StartTLS()
			defer site.Close()
			opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), RealityWebsite: &conf.RealityWebsite{ServerName: siteName, Port: sitePort, ProxyProtocol: tc.siteProxy}}
			opts.XrayOptions.EnableProxyProtocol = tc.upstreamProxy
			nodePort := freeLoopbackPort(t)
			if testPort := os.Getenv("N2X_TEST_REALITY_PORT"); testPort != "" {
				nodePort, err = strconv.Atoi(testPort)
				if err != nil {
					t.Fatal(err)
				}
			}
			address := startNamedRealityNode(t, host, port, base64.RawURLEncoding.EncodeToString(key.Bytes()), flow, opts, realityName, siteName, nodePort)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			dial := func() (net.Conn, *net.TCPAddr) {
				t.Helper()
				dialer := net.Dialer{Timeout: time.Second}
				// Linux routes the entire 127/8 prefix to loopback. A separate
				// source address exposes any accidental redial to the proxy.
				if runtime.GOOS == "linux" {
					dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}
				}
				c, err := dialer.DialContext(ctx, "tcp4", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				c.SetDeadline(time.Now().Add(15 * time.Second))
				source := c.LocalAddr().(*net.TCPAddr)
				if tc.upstreamProxy {
					source = &net.TCPAddr{IP: net.ParseIP("192.0.2.19"), Port: 52671}
					if _, err := proxyproto.HeaderProxyFromAddrs(2, source, c.RemoteAddr()).WriteTo(c); err != nil {
						t.Fatal(err)
					}
				}
				return c, source
			}

			awaitWebsitePage(t, address, siteName, "/website", func() (net.Conn, error) { c, _ := dial(); return c, nil }, "/website")
			// An unfinished connection must not hold up either route.
			slow, _ := dial()
			defer slow.Close()
			raw, source := dial()
			roots := x509.NewCertPool()
			roots.AddCert(site.Certificate())
			browser := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: siteName})
			defer browser.Close()
			if err := browser.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(browser, "GET /website HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", siteName); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(browser), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			var sni, path, remote string
			if _, err := fmt.Sscan(string(body), &sni, &path, &remote); err != nil || resp.StatusCode != 200 || sni != siteName || path != "/website" {
				t.Fatalf("website %d %q", resp.StatusCode, body)
			}
			if tc.siteProxy && remote != source.String() {
				t.Fatalf("website saw %s, want %s", remote, source)
			}
			t.Logf("HTTPS %s via %s: %d, website peer %s", sni, address, resp.StatusCode, remote)

			raw, source = dial()
			logger := log.NewNOPFactory().Logger()
			cfg, err := boxTLS.NewRealityClient(ctx, logger, address, option.OutboundTLSOptions{Enabled: true, ServerName: realityName, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "0123456789abcdef"}})
			if err != nil {
				t.Fatal(err)
			}
			secure, err := boxTLS.ClientHandshake(ctx, raw, cfg)
			if err != nil {
				t.Fatal(err)
			}
			client, err := vless.NewClient(singMuxTestPassword, flow, logger)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialConn(secure, M.ParseSocksaddr(startTCPEcho(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			const payload = "authenticated REALITY transfer"
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
				t.Fatalf("VLESS echo %q: %v", reply, err)
			}
			limit, err := limiter.GetLimiter("xray-reality-wire-" + flow)
			if err != nil {
				t.Fatal(err)
			}
			devices, err := limit.GetOnlineDevice()
			if err != nil || len(*devices) != 1 || (*devices)[0].UID != 1 || (*devices)[0].IP != source.IP.String() {
				t.Fatalf("online devices %v, want %s: %v", devices, source.IP, err)
			}
			t.Logf("VLESS Vision %s via %s: echo OK, online IP %s", realityName, address, (*devices)[0].IP)
		})
	}
}

// SetFallbackRoots affects the whole process. Run this wire test in its own
// process and use only the locally issued certificate for origin verification.
func websiteTestCertificate(t *testing.T, name string) (tls.Certificate, bool) {
	t.Helper()
	if os.Getenv("N2X_WEBSITE_TEST_CHILD") != t.Name() {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run", "^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), "N2X_WEBSITE_TEST_CHILD="+t.Name(), "GODEBUG="+os.Getenv("GODEBUG")+",x509usefallbackroots=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{}, false
	}
	leaf, err := cert.Generate(nil, cert.DNSNames(name))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leaf.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pair.Leaf)
	x509.SetFallbackRoots(roots)
	return pair, true
}

func awaitWebsitePage(t *testing.T, address, name, path string, dial func() (net.Conn, error), expected string) {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) { return dial() }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	timeout := time.Now().Add(18 * time.Second)
	var last string
	for time.Now().Before(timeout) {
		r, err := client.Get("https://" + name + path)
		if err == nil {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			last = string(body)
			if r.StatusCode == 200 && strings.Contains(last, expected) {
				return
			}
		} else {
			last = err.Error()
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("%s: expected %q, got %q", address, expected, last)
}

func TestRealityWebsiteAutomaticFailover(t *testing.T) {
	const name = "us-pro-uc.nom-loc.com"
	const targetName = "www.analog.com"
	const flow = "xtls-rprx-vision"
	pair, child := websiteTestCertificate(t, name)
	if !child {
		return
	}
	newSite := func(body string) *httptest.Server {
		site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		site.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		return site
	}
	target := newSite("original reality target")
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	host, port, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	site := newSite("local node website")
	originAddress := site.Listener.Addr().String()
	t.Setenv("N2X_ARTX_DECOY_HTTPS_LISTEN", originAddress)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	listenPort := freeLoopbackPort(t)
	if os.Getenv("N2X_TEST_REALITY_PORT") == "443" {
		listenPort = 443
	} else {
		opts.RealityWebsite = &conf.RealityWebsite{}
	}
	addr := startNamedRealityNode(t, host, port, base64.RawURLEncoding.EncodeToString(key.Bytes()), flow, opts, targetName, name, listenPort)
	defer site.Close()
	dial := func() (net.Conn, error) { return net.DialTimeout("tcp", addr, time.Second) }
	echo := startTCPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connect := func() net.Conn {
		t.Helper()
		raw, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		logger := log.NewNOPFactory().Logger()
		cfg, err := boxTLS.NewRealityClient(ctx, logger, addr, option.OutboundTLSOptions{Enabled: true, ServerName: targetName, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "0123456789abcdef"}})
		if err != nil {
			t.Fatal(err)
		}
		secure, err := boxTLS.ClientHandshake(ctx, raw, cfg)
		if err != nil {
			t.Fatal(err)
		}
		client, err := vless.NewClient(singMuxTestPassword, flow, logger)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.DialConn(secure, M.ParseSocksaddr(echo))
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	echoOn := func(conn net.Conn, phase string) {
		t.Helper()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := io.WriteString(conn, phase); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, len(phase))
		if _, err := io.ReadFull(conn, body); err != nil || string(body) != phase {
			t.Fatalf("%s: %q %v", phase, body, err)
		}
		conn.SetDeadline(time.Time{})
	}
	kept := connect()
	defer kept.Close()
	check := func(phase, page string) {
		t.Helper()
		awaitWebsitePage(t, addr, name, "/", dial, page)
		echoOn(kept, phase)
		newConn := connect()
		echoOn(newConn, phase)
		newConn.Close()
		t.Logf("%s: browser=%s; existing and new Vision connections OK", phase, page)
	}
	check("website offline at startup", "original reality target")
	site.StartTLS()
	check("website available", "local node website")
	site.Close()
	check("website stopped", "original reality target")
	restart := newSite("recovered website")
	restart.Listener.Close()
	restart.Listener, err = net.Listen("tcp", originAddress)
	if err != nil {
		t.Fatal(err)
	}
	restart.StartTLS()
	defer restart.Close()
	check("website recovered", "recovered website")
}
