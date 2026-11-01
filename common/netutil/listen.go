package netutil

import (
	"context"
	"net"
)

// ListenTCP creates an auxiliary listener without inheriting Go's MPTCP default.
// Explicit socket settings take precedence over GODEBUG (CVE-2026-98432).
func ListenTCP(network, address string) (net.Listener, error) {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	return config.Listen(context.Background(), network, address)
}
