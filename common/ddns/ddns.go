// Package ddns maintains one explicitly enabled A or AAAA record per config.
package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	config   conf.DDNSConfig
	client   *http.Client
	ipClient *http.Client
}

func New(config conf.DDNSConfig) (*Service, error) {
	config = config.Effective(nil)
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Refuse redirects so an API credential cannot follow a redirected request.
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	client.Transport = http.DefaultTransport.(*http.Transport).Clone()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Detect this machine's IP, rather than a proxy's IP.
	network := "tcp4"
	if config.RecordType == "AAAA" {
		network = "tcp6"
	}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	}
	ipClient := *client
	ipClient.Transport = transport
	return &Service{config: config, client: client, ipClient: &ipClient}, nil
}

func (s *Service) Close() {
	s.client.CloseIdleConnections()
	s.ipClient.CloseIdleConnections()
}

// Update always reads the provider's current record, so external edits or
// deletions are repaired even if this machine's address did not change.
func (s *Service) Update(ctx context.Context) (err error) {
	if !s.config.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			message := err.Error()
			for _, value := range s.config.DNSEnv {
				if value != "" {
					message = strings.ReplaceAll(message, value, "[REDACTED]")
				}
			}
			err = errors.New(message)
		}
	}()
	ip, err := s.detectIP(ctx)
	if err != nil {
		return err
	}
	switch s.config.Provider {
	case "cloudflare":
		return s.updateCloudflare(ctx, ip)
	case "alidns":
		return s.updateAliDNS(ctx, ip)
	default:
		return errors.New("unsupported DDNS provider")
	}
}

func (s *Service) detectIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.IPURL, nil)
	if err != nil {
		return "", errors.New("invalid DDNS IP detection URL")
	}
	rsp, err := s.ipClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DDNS public IP detection failed: %w", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DDNS IP detection returned HTTP %d", rsp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(rsp.Body, 256))
	if err != nil {
		return "", errors.New("read DDNS IP detection response failed")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	ip = ip.Unmap()
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return "", errors.New("DDNS IP detection did not return a public IP address")
	}
	if s.config.RecordType == "A" && !ip.Is4() || s.config.RecordType == "AAAA" && !ip.Is6() {
		return "", errors.New("DDNS detected IP family does not match RecordType")
	}
	return ip.String(), nil
}

func (s *Service) doJSON(req *http.Request, dst any) error {
	rsp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("DDNS API request failed: %w", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		return fmt.Errorf("DDNS API returned HTTP %d", rsp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(rsp.Body, 1<<20)).Decode(dst); err != nil {
		return errors.New("invalid DDNS API response")
	}
	return nil
}

func sameIP(a, b string) bool {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	return errX == nil && errY == nil && x.Unmap() == y.Unmap()
}

func (s *Service) recordUpdated(ip string, err error) error {
	if err == nil {
		log.WithFields(log.Fields{"domain": s.config.Domain, "provider": s.config.Provider,
			"record_type": s.config.RecordType, "ip": ip}).Info("DDNS record updated")
	}
	return err
}
