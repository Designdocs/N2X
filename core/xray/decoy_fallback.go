package xray

import (
	"strings"

	"github.com/Designdocs/N2X/decoy"
)

const decoySelector = decoy.Selector

// resolveFallbackDest expands the companion web service selector to the
// resolved loopback address of the installed service. Every other destination
// is passed through untouched, so hand written ports, host:port pairs and unix
// socket paths keep working exactly as before.
func resolveFallbackDest(dest string) (string, error) {
	if strings.TrimSpace(dest) != decoySelector {
		return dest, nil
	}
	return decoy.ResolveListenAddress()
}
