package xray

import (
	"fmt"
	"net/url"
	"os"
	"strings"

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

// enableTransportDecoyFallback points the core's transport level fallback at the
// installed companion web service.
//
// The switch travels in an environment variable rather than in the stream
// settings because carrying it through the transport config would mean editing
// two config.proto files and infra/conf/transport_internet.go in the core fork,
// which is the part of that tree upstream rewrites most.
//
// The cost of that choice is that the setting is process wide: once any ws or
// xhttp node turns it on, every ws and xhttp inbound in this process serves the
// companion site on a rejection. Single node installs are homogeneous in
// practice, and the alternative is a merge conflict on every upstream sync. See
// scripts/decoy-transport-fallback.md in the core fork.
func enableTransportDecoyFallback(options *conf.XrayOptions, network string) error {
	if options == nil || !options.DecoyFallback {
		return nil
	}
	if !transportDecoyFallbackNetworks[strings.ToLower(strings.TrimSpace(network))] {
		return nil
	}

	origin, err := decoyTransportFallbackOrigin()
	if err != nil {
		return err
	}
	return os.Setenv(decoyfallback.OriginEnvironment, origin)
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
