package xray

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/decoy"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const (
	artXDecoySelector          = decoySelector
	artXDecoyListenEnvironment = decoy.ListenAddressEnvironment
)

func resolveArtXFallback(config panel.ArtXFallback, profile string) (*coreConf.ArtXFallbackConfig, error) {
	if !config.Enabled {
		return nil, nil
	}

	origin := strings.TrimSpace(config.Origin)
	if origin == "" {
		return nil, errors.New("artx fallback origin is required when enabled")
	}
	if origin == artXDecoySelector {
		return resolveInstalledDecoyFallback(profile)
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("invalid artx fallback origin: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("artx fallback origin must use HTTPS")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("artx fallback origin requires a host")
	}
	if parsed.User != nil {
		return nil, errors.New("artx fallback origin must not contain credentials")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("artx fallback origin must not contain a fragment")
	}

	return &coreConf.ArtXFallbackConfig{Enabled: true, Origin: origin}, nil
}

func resolveInstalledDecoyFallback(profile string) (*coreConf.ArtXFallbackConfig, error) {
	listenAddress, err := decoy.ResolveListenAddress()
	if err != nil {
		return nil, err
	}

	originURL := &url.URL{Scheme: "http", Host: listenAddress, Path: "/"}
	query := originURL.Query()
	query.Set("profile", canonicalArtXProfile(profile))
	originURL.RawQuery = query.Encode()
	origin := originURL.String()
	return &coreConf.ArtXFallbackConfig{Enabled: true, Origin: origin}, nil
}
