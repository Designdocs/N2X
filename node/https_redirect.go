package node

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

const defaultHTTPSRedirectListenAddress = ":443"

type httpsRedirectEntry struct {
	host        string
	port        int
	certificate *tls.Certificate
}

type httpsRedirectManager struct {
	mu            sync.RWMutex
	listenAddress string
	entries       map[string]httpsRedirectEntry
	blockers      map[string]struct{}
	server        *http.Server
	listener      net.Listener
}

func (c *Controller) prepareHTTPSRedirect(nodeInfo *panel.NodeInfo) {
	if c.httpsRedirectManager == nil {
		return
	}
	c.httpsRedirectManager.Prepare(c.tag, nodeInfo)
}

func (c *Controller) refreshHTTPSRedirect(nodeInfo *panel.NodeInfo) {
	if c.httpsRedirectManager == nil {
		return
	}
	if err := c.httpsRedirectManager.Upsert(
		c.tag,
		nodeInfo,
		c.effectiveCertConfig(nodeInfo),
	); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("HTTPS redirect is unavailable; ArtX remains active on its public port")
	}
}

func newHTTPSRedirectManager(listenAddress string) *httpsRedirectManager {
	return &httpsRedirectManager{
		listenAddress: listenAddress,
		entries:       make(map[string]httpsRedirectEntry),
		blockers:      make(map[string]struct{}),
	}
}

func (manager *httpsRedirectManager) Prepare(tag string, nodeInfo *panel.NodeInfo) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if blocksHTTPSRedirect(nodeInfo) {
		manager.blockers[tag] = struct{}{}
		delete(manager.entries, tag)
		manager.stopLocked()
		return
	}
	delete(manager.blockers, tag)
}

func (manager *httpsRedirectManager) Upsert(
	tag string,
	nodeInfo *panel.NodeInfo,
	certConfig *conf.CertConfig,
) error {
	if blocksHTTPSRedirect(nodeInfo) {
		manager.Prepare(tag, nodeInfo)
		if hasHTTPSRedirectEndpoint(nodeInfo) && nodeInfo.ArtX.PublicPort != 443 {
			return errors.New("HTTPS redirect cannot share port 443 with the ArtX listener")
		}
		return nil
	}
	if !hasHTTPSRedirectEndpoint(nodeInfo) {
		return manager.Remove(tag)
	}

	host, err := normalizeRedirectHost(nodeInfo.ArtX.PublicHost)
	if err != nil {
		return err
	}
	if certConfig == nil || certConfig.CertFile == "" || certConfig.KeyFile == "" {
		return errors.New("HTTPS redirect requires certificate and key files")
	}
	certificate, err := tls.LoadX509KeyPair(certConfig.CertFile, certConfig.KeyFile)
	if err != nil {
		return fmt.Errorf("load HTTPS redirect certificate: %w", err)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	for existingTag, entry := range manager.entries {
		if existingTag != tag && entry.host == host && entry.port != nodeInfo.ArtX.PublicPort {
			return fmt.Errorf("HTTPS redirect host %q already targets port %d", host, entry.port)
		}
	}

	delete(manager.blockers, tag)
	manager.entries[tag] = httpsRedirectEntry{
		host:        host,
		port:        nodeInfo.ArtX.PublicPort,
		certificate: &certificate,
	}
	if len(manager.blockers) != 0 || manager.server != nil {
		return nil
	}
	return manager.startLocked()
}

func (manager *httpsRedirectManager) Remove(tag string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.entries, tag)
	delete(manager.blockers, tag)
	if len(manager.entries) == 0 {
		manager.stopLocked()
		return nil
	}
	if len(manager.blockers) == 0 && manager.server == nil {
		return manager.startLocked()
	}
	return nil
}

func (manager *httpsRedirectManager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	manager.entries = make(map[string]httpsRedirectEntry)
	manager.blockers = make(map[string]struct{})
	manager.stopLocked()
	return nil
}

func (manager *httpsRedirectManager) Address() string {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	if manager.listener == nil {
		return ""
	}
	return manager.listener.Addr().String()
}

func (manager *httpsRedirectManager) startLocked() error {
	listener, err := net.Listen("tcp", manager.listenAddress)
	if err != nil {
		return fmt.Errorf("listen for HTTPS redirects on %s: %w", manager.listenAddress, err)
	}

	server := &http.Server{
		Handler:           manager,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: manager.getCertificate,
		},
	}
	manager.server = server
	manager.listener = listener

	go func() {
		err := server.ServeTLS(listener, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("HTTPS redirect listener stopped")
		}
		manager.mu.Lock()
		if manager.server == server {
			manager.server = nil
			manager.listener = nil
		}
		manager.mu.Unlock()
	}()

	return nil
}

func (manager *httpsRedirectManager) stopLocked() {
	if manager.server == nil {
		manager.listener = nil
		return
	}
	server := manager.server
	manager.server = nil
	manager.listener = nil
	_ = server.Close()
}

func (manager *httpsRedirectManager) getCertificate(
	clientHello *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	host, err := normalizeRedirectHost(clientHello.ServerName)
	if err != nil {
		return nil, errors.New("unrecognized HTTPS redirect server name")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, entry := range manager.entries {
		if entry.host == host {
			return entry.certificate, nil
		}
	}
	return nil, errors.New("unrecognized HTTPS redirect server name")
}

func (manager *httpsRedirectManager) ServeHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	host, err := normalizeRedirectHost(request.Host)
	if err != nil {
		response.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	if request.TLS == nil {
		response.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	serverName, err := normalizeRedirectHost(request.TLS.ServerName)
	if err != nil || serverName != host {
		response.WriteHeader(http.StatusMisdirectedRequest)
		return
	}

	entry, ok := manager.entryForHost(host)
	if !ok {
		response.WriteHeader(http.StatusMisdirectedRequest)
		return
	}

	location := "https://" + net.JoinHostPort(entry.host, strconv.Itoa(entry.port)) + request.URL.RequestURI()
	response.Header().Set("Location", location)
	response.WriteHeader(http.StatusMovedPermanently)
}

func (manager *httpsRedirectManager) entryForHost(host string) (httpsRedirectEntry, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, entry := range manager.entries {
		if entry.host == host {
			return entry, true
		}
	}
	return httpsRedirectEntry{}, false
}

func hasHTTPSRedirectEndpoint(nodeInfo *panel.NodeInfo) bool {
	return nodeInfo != nil &&
		nodeInfo.Type == "artx" &&
		nodeInfo.ArtX != nil &&
		strings.TrimSpace(nodeInfo.ArtX.PublicHost) != "" &&
		nodeInfo.ArtX.PublicPort >= 1 &&
		nodeInfo.ArtX.PublicPort <= 65535
}

func blocksHTTPSRedirect(nodeInfo *panel.NodeInfo) bool {
	if nodeInfo == nil {
		return false
	}
	if nodeInfo.Common != nil && nodeInfo.Common.ServerPort == 443 {
		return true
	}
	return nodeInfo.Type == "artx" &&
		nodeInfo.ArtX != nil &&
		nodeInfo.ArtX.PublicPort == 443
}

func normalizeRedirectHost(value string) (string, error) {
	host := strings.TrimSpace(value)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return "", errors.New("invalid HTTPS redirect host")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("invalid HTTPS redirect host")
	}
	return host, nil
}
