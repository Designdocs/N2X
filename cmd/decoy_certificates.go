package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Designdocs/N2X/conf"
)

const managedDecoyCertificateRefresh = 30 * time.Second

type managedDecoyCertificate struct {
	name string
	pair *tls.Certificate
}

type managedDecoyCertificates struct {
	directory string
	roots     *x509.CertPool // nil uses the system trust store

	mu           sync.Mutex
	refreshAt    time.Time
	certificates []managedDecoyCertificate
}

func (store *managedDecoyCertificates) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, errors.New("managed companion HTTPS certificates require a TLS server name")
	}

	store.mu.Lock()
	now := time.Now()
	if !now.Before(store.refreshAt) {
		store.refresh(now)
		store.refreshAt = now.Add(managedDecoyCertificateRefresh)
	}
	certificates := store.certificates
	store.mu.Unlock()

	for _, certificate := range certificates {
		leaf := certificate.pair.Leaf
		if !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) && hello.SupportsCertificate(certificate.pair) == nil {
			return certificate.pair, nil
		}
	}
	return nil, fmt.Errorf("no trusted companion HTTPS certificate in %s for %q", store.directory, hello.ServerName)
}

func (store *managedDecoyCertificates) refresh(now time.Time) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		store.certificates = nil
		return
	}
	previous := make(map[string]*tls.Certificate, len(store.certificates))
	for _, certificate := range store.certificates {
		previous[certificate.name] = certificate.pair
	}

	var certificates []managedDecoyCertificate
	for _, entry := range entries {
		name := entry.Name()
		key, ok := conf.ManagedCertificateKeyName(name)
		if entry.IsDir() || !ok {
			continue
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(store.directory, name), filepath.Join(store.directory, key))
		if err != nil {
			// Renewal may temporarily leave the certificate and key out of sync.
			if old := previous[name]; old != nil && !errors.Is(err, os.ErrNotExist) && store.trusted(old, now) {
				certificates = append(certificates, managedDecoyCertificate{name: name, pair: old})
			}
			continue
		}
		if store.trusted(&pair, now) {
			certificates = append(certificates, managedDecoyCertificate{name: name, pair: &pair})
		}
	}
	store.certificates = certificates
}

func (store *managedDecoyCertificates) trusted(pair *tls.Certificate, now time.Time) bool {
	leaf := pair.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return false
		}
		pair.Leaf = leaf
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if certificate, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(certificate)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: store.roots, Intermediates: intermediates, CurrentTime: now})
	return err == nil
}
