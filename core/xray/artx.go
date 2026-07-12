package xray

import (
	"crypto/md5"
	"errors"
	"fmt"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const (
	artXUnderlayAnyTLS     = "anytls"
	artXUnderlayWire       = "artx-wire"
	artXWireVersion        = 1
	artXWireProfileVersion = 1
)

const (
	artXProfileBalanced = "balanced"
	artXProfileWeb      = "web"
	artXProfileMedia    = "media"
	artXProfileRealtime = "realtime"
)

// artXProfilePaddingSchemes maps each ArtX profile to a distinct AnyTLS padding
// scheme. This is the first ArtX↔AnyTLS isolation step (P1#4): profile stops
// being a pure label and starts shaping the on-wire packet-size distribution,
// so ArtX traffic no longer matches the native AnyTLS default scheme (nor its
// md5 fingerprint). Each scheme stays within AnyTLS' padding DSL (stop=N plus
// one size list per packet index) while diverging in first flight, sustained
// record sizes and stop point along the profile intent:
//   - balanced: general web/API/app, moderate padding.
//   - web:      short requests, low sustained throughput, early stop.
//   - media:    download-heavy, smooth large records, late stop.
//   - realtime: bidirectional small packets, minimal padding, earliest stop.
var artXProfilePaddingSchemes = map[string][]string{
	artXProfileBalanced: {
		"stop=7",
		"0=34-64",
		"1=128-512",
		"2=256-768,c,512-1200,c,512-1200,c,512-1200",
		"3=16-16,480-960",
		"4=480-1024",
		"5=480-1024",
		"6=480-1024",
	},
	artXProfileWeb: {
		"stop=4",
		"0=30-48",
		"1=64-256",
		"2=96-320,c,128-512",
		"3=48-192",
	},
	artXProfileMedia: {
		"stop=10",
		"0=40-72",
		"1=256-768",
		"2=800-1400,c,900-1460,c,900-1460,c,900-1460,c,900-1460",
		"3=64-64,900-1460",
		"4=900-1460",
		"5=900-1460",
		"6=900-1460",
		"7=900-1460",
		"8=900-1460",
		"9=900-1460",
	},
	artXProfileRealtime: {
		"stop=3",
		"0=28-40",
		"1=48-160",
		"2=32-128,c,48-192",
	},
}

func buildArtX(option *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	if nodeInfo.ArtX == nil {
		return errors.New("missing artx node settings")
	}

	switch normalizeArtXUnderlay(nodeInfo.ArtX.Underlay) {
	case artXUnderlayAnyTLS:
		if err := buildAnyTLSUnderlayInbound(inbound, anyTLSUnderlayConfig{
			PaddingScheme: resolveArtXPaddingScheme(nodeInfo.ArtX),
		}); err != nil {
			return err
		}
		logArtXObservation(newArtXObservation(nodeInfo.ArtX))
		return nil
	case artXUnderlayWire:
		return buildArtXWireInbound(option, nodeInfo, inbound)
	default:
		return fmt.Errorf("unsupported artx underlay: %s", nodeInfo.ArtX.Underlay)
	}
}

// ArtXObservation is the node-side observability summary emitted once per ArtX
// inbound build (P1#5). It lets operators confirm, from structured logs, which
// behavior profile and padding fingerprint a node is actually running — the
// baseline needed to tell whether a later wire-protocol change altered on-wire
// behavior, and to verify ArtX has diverged from native AnyTLS. It carries no
// user keys, tokens or payload, per the ArtX logging constraint.
type ArtXObservation struct {
	Protocol         string `json:"protocol"`           // always "artx"
	Underlay         string `json:"underlay"`           // "anytls" scaffold for now
	Profile          string `json:"profile"`            // balanced|web|media|realtime
	ProfileVersion   int    `json:"profile_version"`    //
	PaddingSchemeMD5 string `json:"padding_scheme_md5"` // fingerprint negotiated on wire
	PaddingSource    string `json:"padding_source"`     // "profile" | "override"
	FallbackEnabled  bool   `json:"fallback_enabled"`   // decoy origin configured
}

func newArtXObservation(node *panel.ArtXNode) ArtXObservation {
	source := "profile"
	if len(node.PaddingScheme) > 0 {
		source = "override"
	}
	return ArtXObservation{
		Protocol:         "artx",
		Underlay:         normalizeArtXUnderlay(node.Underlay),
		Profile:          normalizeArtXProfile(node.Profile),
		ProfileVersion:   node.ProfileVersion,
		PaddingSchemeMD5: paddingSchemeMD5(resolveArtXPaddingScheme(node)),
		PaddingSource:    source,
		FallbackEnabled:  node.Fallback.Enabled,
	}
}

// paddingSchemeMD5 mirrors xray anytls: the padding layer joins the scheme lines
// with "\n" and md5s the result, so this value equals the fingerprint actually
// negotiated on the wire (see proxy/anytls/padding.go).
func paddingSchemeMD5(scheme []string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(scheme, "\n"))))
}

func logArtXObservation(obs ArtXObservation) {
	log.WithFields(log.Fields{
		"protocol":           obs.Protocol,
		"underlay":           obs.Underlay,
		"profile":            obs.Profile,
		"profile_version":    obs.ProfileVersion,
		"padding_scheme_md5": obs.PaddingSchemeMD5,
		"padding_source":     obs.PaddingSource,
		"fallback_enabled":   obs.FallbackEnabled,
	}).Info("artx inbound observation")
}

// resolveArtXPaddingScheme keeps an explicit operator override (padding pinned
// on the panel) authoritative, and otherwise derives the scheme from the node's
// profile. Because the panel no longer injects the native AnyTLS default scheme
// for ArtX nodes, the common path is profile-derived.
func resolveArtXPaddingScheme(node *panel.ArtXNode) []string {
	if len(node.PaddingScheme) > 0 {
		return node.PaddingScheme
	}
	return artXProfilePaddingScheme(node.Profile)
}

func artXProfilePaddingScheme(profile string) []string {
	if scheme, ok := artXProfilePaddingSchemes[normalizeArtXProfile(profile)]; ok {
		return scheme
	}
	return artXProfilePaddingSchemes[artXProfileBalanced]
}

func normalizeArtXProfile(profile string) string {
	return strings.ToLower(strings.TrimSpace(profile))
}

func normalizeArtXUnderlay(underlay string) string {
	normalized := strings.ToLower(strings.TrimSpace(underlay))
	if normalized == "" {
		return artXUnderlayAnyTLS
	}
	return normalized
}

func buildArtXUsers(tag string, userInfo []panel.UserInfo, nodeInfo *panel.NodeInfo) []*protocol.User {
	if artXWireHandlesTLS(nodeInfo) {
		return buildArtXWireUsers(tag, userInfo)
	}
	return buildAnyTLSUnderlayUsers(tag, userInfo)
}
