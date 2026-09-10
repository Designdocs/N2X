package xray

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

// transportDecoyFallbackNetworks lists the transports that answer an unmatched
// Host or Path themselves, before any proxy protocol runs. A protocol level
// fallback can never see those requests, so on these transports the companion
// web service has to be wired in at the transport instead.
//
// tcp is absent because the protocol fallbacks list already covers it. grpc has
// no equivalent rejection hook, and httpupgrade rejects on a raw connection
// rather than through an http.Handler, so neither is covered yet.
var transportDecoyFallbackNetworks = map[string]bool{
	"ws":        true,
	"splithttp": true,
	"xhttp":     true,
}

// panelFallbackOptions preserves local defaults when an older panel omits the
// switch. Copy both structs so a reload can return to the original local value.
func panelFallbackOptions(options *conf.Options, info *panel.NodeInfo) *conf.Options {
	if (info.Type != "vless" && info.Type != "trojan") || info.Common == nil || info.Common.DecoyFallback == nil {
		return options
	}
	resolved := *options
	xray := conf.XrayOptions{}
	if options.XrayOptions != nil {
		xray = *options.XrayOptions
	}
	xray.DecoyFallback = *info.Common.DecoyFallback
	resolved.XrayOptions = &xray
	return &resolved
}

func transportFallbackOrigin(options *conf.XrayOptions, network string) (string, error) {
	if options == nil || !options.DecoyFallback || !transportDecoyFallbackNetworks[strings.ToLower(strings.TrimSpace(network))] {
		return "", nil
	}
	return decoyTransportFallbackOrigin()
}

// decoyTransportFallbackOrigin builds the origin URL of the installed companion
// web service and checks it against the core's own parser before it is handed
// over. Validating here turns a bad listen address into a startup error rather
// than a fallback that silently keeps returning 404 in production.
//
// No profile is pinned in the query: the companion service reads
// N2X_ARTX_DECOY_PROFILE itself, so an operator changes the page in one place
// for both the protocol and the transport path.
func decoyTransportFallbackOrigin() (string, error) {
	listenAddress, err := decoy.ResolveListenAddress()
	if err != nil {
		return "", err
	}

	origin := (&url.URL{Scheme: "http", Host: listenAddress, Path: "/"}).String()
	if err := decoyfallback.ValidateOrigin(origin); err != nil {
		return "", fmt.Errorf("companion web service origin %q rejected by the core: %w", origin, err)
	}
	return origin, nil
}
