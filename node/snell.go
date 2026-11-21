package node

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Designdocs/N2X/api/panel"
)

func (c *Controller) validateSnellWebsiteChange(next *panel.NodeInfo) error {
	if next.Snell == nil {
		return nil
	}
	if err := next.Snell.ValidateListen(c.Options.ListenIP, next.Common.ServerPort); err != nil {
		return err
	}
	origin, minTLS := snellWebsiteOrigin(next.Snell)
	if origin.ServerPort == 0 {
		return nil
	}
	if c.info != nil {
		previous, previousMinTLS := snellWebsiteOrigin(c.info.Snell)
		if previous == origin && previousMinTLS == minTLS {
			return nil
		}
	}

	// Probe the new TLS origin before deleting the active listener. Its certificate
	// must cover the same SNI that the panel gives to clients.
	address := origin.Address()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		ServerName: origin.ServerName,
		MinVersion: minTLS,
	})
	if err != nil {
		return fmt.Errorf("check Snell website fallback at %s: %w", address, err)
	}
	_ = conn.Close()
	return nil
}

func snellWebsiteOrigin(node *panel.SnellNode) (panel.SnellWebsiteFallback, uint16) {
	if node != nil {
		if node.WebsiteFallback != nil {
			return *node.WebsiteFallback, tls.VersionTLS12
		}
		if outer := node.ShadowTLS; outer != nil && outer.FallbackServerName != "" {
			return panel.SnellWebsiteFallback{
				ServerName: outer.FallbackServerName,
				ServerPort: outer.HandshakePort(),
			}, tls.VersionTLS13
		}
	}
	return panel.SnellWebsiteFallback{}, 0
}
