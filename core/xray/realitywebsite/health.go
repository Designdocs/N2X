package realitywebsite

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Designdocs/N2X/decoy"
	"github.com/pires/go-proxyproto"
)

type origin struct {
	address string
	proxy   bool
}

// Website health never gates listener startup or an authenticated handshake.
func (l *listener) monitor(c *Config) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		addr := c.Address
		if addr == "" {
			addr = companionHTTPSAddress()
		}
		var healthy *origin
		if decoy.ValidateListenAddress(addr) == nil {
			_, text, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(text)
			if port != l.Addr().(*net.TCPAddr).Port {
				// Prefer forwarding real addresses where supported. Remember the
				// working mode to avoid sending incompatible probes every interval.
				wantProxy := true
				if previous := l.site.Load(); previous != nil && previous.address == addr {
					wantProxy = previous.proxy
				}
				candidate := origin{address: addr, proxy: wantProxy}
				if candidate.healthy(l.ctx, c.ServerName) {
					healthy = &candidate
				} else if !c.ProxyProtocol && l.ctx.Err() == nil {
					candidate.proxy = !candidate.proxy
					if candidate.healthy(l.ctx, c.ServerName) {
						healthy = &candidate
					}
				}
			}
		}
		l.site.Store(healthy)
		select {
		case <-ticker.C:
		case <-l.ctx.Done():
			return
		}
	}
}

func (o origin) healthy(parent context.Context, name string) bool {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{ServerName: name},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", o.address)
			if err != nil {
				return nil, err
			}
			if o.proxy {
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, err = proxyproto.HeaderProxyFromAddrs(2, conn.LocalAddr(), conn.RemoteAddr()).WriteTo(conn)
				if err != nil {
					conn.Close()
					return nil, err
				}
				conn.SetWriteDeadline(time.Time{})
			}
			return conn, nil
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, (&url.URL{Scheme: "https", Host: name, Path: "/"}).String(), nil)
	if err != nil {
		return false
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

func companionHTTPSAddress() string {
	if address, ok := os.LookupEnv(decoy.HTTPSListenEnvironment); ok {
		return strings.TrimSpace(address)
	}
	// OpenRC versions that only export the HTTP setting still share the
	// companion service's env file. Read just this literal setting.
	data, err := os.ReadFile("/etc/N2X/artx-decoy.env")
	if err != nil && !os.IsNotExist(err) {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), decoy.HTTPSListenEnvironment+"="); ok {
			return strings.TrimSpace(value)
		}
	}
	return decoy.DefaultHTTPSListenAddress
}
