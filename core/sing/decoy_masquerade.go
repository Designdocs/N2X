package sing

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Designdocs/N2X/decoy"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// expandDecoyMasquerade turns the companion web service selector into the
// origin of the service actually installed on this host.
//
// sing-box only understands file, http and https URLs here, so "n2x://decoy"
// would otherwise fail the node. Expanding it means an operator points the
// Hysteria2 masquerade at the built-in site the same way an xray fallback does
// — without having to know which port the service ended up on, and without
// having to update every node when that port changes. Every other value is
// passed through untouched.
//
// Both spellings are covered: the bare URL string a panel field holds, and the
// object form with an explicit proxy URL.
func expandDecoyMasquerade(raw json.RawMessage) (json.RawMessage, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		// Not the string form; the object form is handled after decoding.
		return raw, nil
	}
	origin, replaced, err := decoyMasqueradeOrigin(value)
	if err != nil || !replaced {
		return raw, err
	}
	encoded, err := json.Marshal(origin)
	if err != nil {
		return nil, fmt.Errorf("encode companion web service origin %q: %w", origin, err)
	}
	return encoded, nil
}

// expandDecoyMasqueradeProxy does the same for a decoded object masquerade,
// which carries its URL in a field rather than as the whole value.
func expandDecoyMasqueradeProxy(masquerade *option.Hysteria2Masquerade) error {
	if masquerade.Type != C.Hysterai2MasqueradeTypeProxy {
		return nil
	}
	origin, replaced, err := decoyMasqueradeOrigin(masquerade.ProxyOptions.URL)
	if err != nil || !replaced {
		return err
	}
	masquerade.ProxyOptions.URL = origin
	return nil
}

// decoyMasqueradeOrigin reports the HTTP origin the selector stands for. The
// second result says whether the value was the selector at all, so a caller
// can leave anything else exactly as the operator wrote it.
func decoyMasqueradeOrigin(value string) (string, bool, error) {
	if strings.TrimSpace(value) != decoy.Selector {
		return "", false, nil
	}
	address, err := decoy.ResolveListenAddress()
	if err != nil {
		return "", false, err
	}
	return (&url.URL{Scheme: "http", Host: address, Path: "/"}).String(), true, nil
}
