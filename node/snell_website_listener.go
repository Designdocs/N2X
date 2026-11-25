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

const snellWebsiteRetryInterval = 2 * time.Second

// Nodes on the same VPS can share a loopback port, even with different SNI.
type snellWebsites struct {
	mu    sync.Mutex
	ports map[string]*snellWebsitePort
	roots *x509.CertPool
}

type snellWebsitePort struct {
	server *decoy.Server
	stop   chan struct{}
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
		if err := w.listen(addr, port); err != nil && !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
		if w.ports == nil {
			w.ports = make(map[string]*snellWebsitePort)
		}
		w.ports[addr] = port
	}
	var certFile, keyFile string
	if cfg != nil && cfg.CertMode != "" && cfg.CertMode != "none" {
		certFile, keyFile = cfg.CertFile, cfg.KeyFile
	}
	lease := &snellWebsiteLease{owner: w, origin: origin}
	port.users[lease] = websitecert.New(conf.ManagedCertificateDirectory, certFile, keyFile)
	return lease, nil
}

// Caller holds w.mu. Binding the socket is the check for availability.
func (w *snellWebsites) listen(addr string, port *snellWebsitePort) error {
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
	if err != nil {
		return err
	}
	port.server = server
	go func() {
		if err := server.Serve(); err != nil {
			log.WithError(err).Errorf("serve Snell website at %s", addr)
		}
	}()
	return nil
}

// Watch only after the external TLS origin has passed validation and the
// panel configuration has been applied. One watcher serves all nodes on a port.
func (lease *snellWebsiteLease) watchExternal() {
	if lease == nil {
		return
	}
	w := lease.owner
	addr := lease.origin.Address()
	w.mu.Lock()
	defer w.mu.Unlock()
	port := w.ports[addr]
	if port.server != nil || port.stop != nil {
		return
	}
	stop := make(chan struct{})
	port.stop = stop
	go func() {
		ticker := time.NewTicker(snellWebsiteRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				w.mu.Lock()
				if w.ports[addr] != port {
					w.mu.Unlock()
					return
				}
				err := w.listen(addr, port)
				w.mu.Unlock()
				if err == nil {
					log.Infof("Started Snell website on released port %s", addr)
					return
				}
				if !errors.Is(err, syscall.EADDRINUSE) {
					log.WithError(err).Warnf("Cannot start Snell website at %s", addr)
				}
			}
		}
	}()
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
		if port.stop != nil {
			close(port.stop)
		}
		if port.server == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = port.server.Shutdown(ctx)
	}
}
