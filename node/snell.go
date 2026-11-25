package node

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/file"
)

// Keep the previous listener until the replacement node and roster are active.
type snellWebsiteChange struct {
	origin panel.SnellWebsiteFallback
	minTLS uint16
	lease  *snellWebsiteLease
}

func (change *snellWebsiteChange) discard() {
	if change != nil {
		change.lease.release()
	}
}

func (change *snellWebsiteChange) apply(c *Controller) {
	if change == nil {
		return
	}
	c.websiteLease.release()
	c.websiteLease, change.lease = change.lease, nil
	c.websiteOrigin, c.websiteTLS = change.origin, change.minTLS
}

func (c *Controller) prepareSnellWebsite(next *panel.NodeInfo) (*snellWebsiteChange, error) {
	if next.Snell != nil {
		if err := next.Snell.ValidateListen(c.Options.ListenIP, next.Common.ServerPort); err != nil {
			return nil, err
		}
	}
	origin, minTLS := snellWebsiteOrigin(next.Snell)
	if origin == c.websiteOrigin && minTLS == c.websiteTLS {
		return nil, nil
	}
	change := &snellWebsiteChange{origin: origin, minTLS: minTLS}
	if origin.ServerPort == 0 {
		return change, nil
	}

	// A newly enabled website can only complete its first handshake after
	// its certificate exists. Keep the active listener until both steps pass.
	if c.managesSnellWebsiteCert(next) {
		cfg := c.localCertConfig()
		existing := file.IsExist(cfg.CertFile) && file.IsExist(cfg.KeyFile)
		if err := c.requestCert(next); err != nil {
			return nil, fmt.Errorf("request Snell website certificate: %w", err)
		}
		if c.renewCertPeriodic == nil && existing {
			// The origin may already have an expired certificate from an earlier run.
			_ = c.renewCertTask(cfg)
		}
	}

	// Probe the new TLS origin before deleting the active listener. Its certificate
	// must cover the same SNI that the panel gives to clients.
	var err error
	change.lease, err = c.websites.acquire(origin, c.localCertConfig())
	if err != nil {
		return nil, err
	}
	address := origin.Address()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		ServerName: origin.ServerName,
		RootCAs:    c.websites.roots,
		MinVersion: minTLS,
	})
	if err != nil {
		change.discard()
		return nil, fmt.Errorf("check Snell website fallback at %s: %w", address, err)
	}
	_ = conn.Close()
	return change, nil
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
