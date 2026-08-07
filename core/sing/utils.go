package sing

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Designdocs/N2X/conf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// detourTagSuffix names the internal inbound a composite protocol chains to.
// Node tags are generated as "[apiHost]-type:id" (see node.Controller), so
// this suffix cannot collide with one; a hand-picked Options.Name would have
// to end in "$detour" to clash.
const detourTagSuffix = "$detour"

func detourTag(tag string) string {
	return tag + detourTagSuffix
}

func processFallback(c *conf.Options, fallbackForALPN map[string]*option.ServerOptions) error {
	for k, v := range c.SingOptions.FallBackConfigs.FallBackForALPN {
		fallbackPort, err := strconv.Atoi(v.ServerPort)
		if err != nil {
			return fmt.Errorf("unable to parse fallbackForALPN server port: %w", err)
		}
		fallbackForALPN[k] = &option.ServerOptions{Server: v.Server, ServerPort: uint16(fallbackPort)}
	}
	return nil
}

// parseDomainStrategy translates the string form used in the N2X config into
// the sing-box enum. conf deliberately keeps this as a string so that
// xray-only builds do not link the sing-box option tree.
func parseDomainStrategy(s string) option.DomainStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "prefer_ipv4":
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case "prefer_ipv6":
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	case "ipv4_only":
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	case "ipv6_only":
		return option.DomainStrategy(C.DomainStrategyIPv6Only)
	default:
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
}

// parseWildcardSNI translates the ShadowTLS wildcard SNI mode.
func parseWildcardSNI(s string) option.WildcardSNI {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "authed":
		return option.ShadowTLSWildcardSNIAuthed
	case "all":
		return option.ShadowTLSWildcardSNIAll
	default:
		return option.ShadowTLSWildcardSNIOff
	}
}

// shadowsocksKeyLength reports the key size a 2022 cipher expects. Non-2022
// ciphers derive their key from the password and have no fixed length.
func shadowsocksKeyLength(cipher string) int {
	switch cipher {
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	default:
		return 16
	}
}
