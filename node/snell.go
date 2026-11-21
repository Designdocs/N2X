package node

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Designdocs/N2X/api/panel"
)

func (c *Controller) validateSnellShadowTLSChange(next *panel.NodeInfo) error {
	if next.Snell == nil || next.Snell.ShadowTLS == nil {
		return nil
	}
	settings := next.Snell.ShadowTLS
	if err := settings.ValidateListen(c.Options.ListenIP, next.Common.ServerPort); err != nil {
		return err
	}
	if settings.FallbackServerName == "" {
		return nil
	}
	if c.info != nil && c.info.Snell != nil {
		current := c.info.Snell.ShadowTLS
		if current != nil && current.Handshake == settings.Handshake && current.FallbackServerName == settings.FallbackServerName {
			return nil
		}
	}

	// Probe the new TLS origin before deleting the active listener. Its certificate
	// must cover the same SNI that the panel gives to clients.
	address := net.JoinHostPort(settings.Handshake.Server, strconv.Itoa(int(settings.HandshakePort())))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		ServerName: settings.FallbackServerName,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return fmt.Errorf("check Snell ShadowTLS website fallback at %s: %w", address, err)
	}
	_ = conn.Close()
	return nil
}
