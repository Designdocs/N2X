package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/websitecert"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	log "github.com/sirupsen/logrus"
)

// Nodes on the same VPS can share a loopback port, even with different SNI.
type snellWebsites struct {
	mu    sync.Mutex
	ports map[string]*snellWebsitePort
	roots *x509.CertPool
}

type snellWebsitePort struct {
	server *decoy.Server
	users  map[*snellWebsiteLease]*websitecert.Store
}

type snellWebsiteLease struct {
	owner  *snellWebsites
	origin panel.SnellWebsiteFallback
}

func (w *snellWebsites) acquire(origin panel.SnellWebsiteFallback, cfg *conf.CertConfig) (*snellWebsiteLease, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	addr := origin.Address()
	port := w.ports[addr]
	if port == nil {
		port = &snellWebsitePort{users: make(map[*snellWebsiteLease]*websitecert.Store)}
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			for user, store := range port.users {
				if strings.EqualFold(hello.ServerName, user.origin.ServerName) {
					if pair, err := store.GetCertificate(hello); err == nil {
						return pair, nil
					}
				}
			}
			return nil, fmt.Errorf("no website certificate for %q at %s", hello.ServerName, addr)
		}
		server, err := decoy.NewServer(decoy.Config{ListenAddress: addr, TLS: &decoy.TLSFiles{GetCertificate: getCertificate}})
		// The caller probes an existing listener before adopting it.
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		port.server = server
		if w.ports == nil {
			w.ports = make(map[string]*snellWebsitePort)
		}
		w.ports[addr] = port
		go func() {
			if err := server.Serve(); err != nil {
				log.WithError(err).Errorf("serve Snell website at %s", addr)
			}
		}()
	}
	var certFile, keyFile string
	if cfg != nil && cfg.CertMode != "" && cfg.CertMode != "none" {
		certFile, keyFile = cfg.CertFile, cfg.KeyFile
	}
	lease := &snellWebsiteLease{owner: w, origin: origin}
	port.users[lease] = websitecert.New(conf.ManagedCertificateDirectory, certFile, keyFile)
	return lease, nil
}

func (lease *snellWebsiteLease) release() {
	if lease == nil {
		return
	}
	w := lease.owner
	w.mu.Lock()
	defer w.mu.Unlock()
	addr := lease.origin.Address()
	port := w.ports[addr]
	delete(port.users, lease)
	if len(port.users) == 0 {
		delete(w.ports, addr)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = port.server.Shutdown(ctx)
	}
}
