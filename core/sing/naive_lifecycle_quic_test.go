//go:build with_quic

package sing

import (
	"crypto/tls"
	"testing"

	"github.com/sagernet/quic-go/http3"
)

func TestNaiveUserUpdatesPreserveHTTP3Tunnel(t *testing.T) {
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.Close()
	testNaiveUserUpdatesPreserveActiveTunnel(t, "udp", transport)
}
