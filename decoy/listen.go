package decoy

import (
	"fmt"
	"os"
	"strings"
)

// Selector is the pseudo destination that stands for "the companion web
// service installed alongside this node". Cores expand it to the resolved
// loopback address, so an operator can point a protocol fallback at the
// built-in site without knowing the port.
const Selector = "n2x://decoy"

// ListenAddressEnvironment names the environment variable that overrides where
// the companion web service listens. The installer writes it to
// /etc/N2X/artx-decoy.env and both the service unit and the core read it from
// there, so every consumer must agree on the name.
const ListenAddressEnvironment = "N2X_ARTX_DECOY_LISTEN"

// ProfileEnvironment names the environment variable that selects which page the
// companion web service serves at "/" when the request does not choose one.
//
// It matters because a browser arriving through a VLESS or Trojan fallback asks
// for "/" with no query string, so this is the only lever an operator has over
// what that connection sees. Leaving every node on the same page makes them all
// answer port 443 with byte-identical content.
const ProfileEnvironment = "N2X_ARTX_DECOY_PROFILE"

// ResolveListenAddress reports the configured loopback address of the installed
// companion web service, falling back to DefaultListenAddress when unset.
//
// Shared by the service itself and by every core that needs to point a protocol
// fallback at it, so a custom port stays consistent across the process tree.
func ResolveListenAddress() (string, error) {
	address := strings.TrimSpace(os.Getenv(ListenAddressEnvironment))
	if address == "" {
		address = DefaultListenAddress
	}
	if err := ValidateListenAddress(address); err != nil {
		return "", fmt.Errorf("invalid companion web service listen address: %w", err)
	}
	return address, nil
}

// resolveConfiguredProfile settles the default page: an explicit value wins,
// then ProfileEnvironment, then balanced. An unrecognised name is an error
// rather than a silent fall back to balanced, so a typo surfaces at startup
// instead of quietly serving the wrong page for months.
func resolveConfiguredProfile(configured string) (contentProfile, error) {
	value := strings.TrimSpace(configured)
	if value == "" {
		value = strings.TrimSpace(os.Getenv(ProfileEnvironment))
	}
	if value == "" {
		return contentProfileBalanced, nil
	}

	profile, ok := parseContentProfile(value)
	if !ok {
		return "", fmt.Errorf(
			"unknown companion web service profile %q, want one of: %s, %s, %s, %s",
			value,
			contentProfileBalanced,
			contentProfileWeb,
			contentProfileMedia,
			contentProfileRealtime,
		)
	}
	return profile, nil
}
