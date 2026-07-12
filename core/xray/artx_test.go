package xray

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildArtXUsesAnyTLSUnderlayWithoutRewritingNodeType(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Type: "artx",
		ArtX: &panel.ArtXNode{
			Underlay:       "anytls",
			Profile:        "balanced",
			ProfileVersion: 1,
			PaddingScheme:  []string{"stop=8", "0=30-30"},
		},
	}
	inbound := &coreConf.InboundDetourConfig{}

	if err := buildArtX(nil, nodeInfo, inbound); err != nil {
		t.Fatalf("buildArtX returned error: %v", err)
	}
	if nodeInfo.Type != "artx" {
		t.Fatalf("expected node type to stay artx, got %q", nodeInfo.Type)
	}
	if inbound.Protocol != "anytls" {
		t.Fatalf("expected Xray underlay protocol anytls, got %q", inbound.Protocol)
	}
	if inbound.StreamSetting == nil || inbound.StreamSetting.Network == nil {
		t.Fatal("expected ArtX to configure a TCP stream")
	}
	if string(*inbound.StreamSetting.Network) != "tcp" {
		t.Fatalf("expected TCP stream, got %q", string(*inbound.StreamSetting.Network))
	}

	var settings struct {
		PaddingScheme []string `json:"paddingScheme"`
	}
	if inbound.Settings == nil {
		t.Fatal("expected ArtX to configure underlay settings")
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal underlay settings failed: %v", err)
	}
	if strings.Join(settings.PaddingScheme, "\n") != "stop=8\n0=30-30" {
		t.Fatalf("unexpected padding scheme: %+v", settings.PaddingScheme)
	}
}

func TestBuildArtXRejectsUnsupportedUnderlay(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Type: "artx",
		ArtX: &panel.ArtXNode{
			Underlay: "custom",
		},
	}

	if err := buildArtX(nil, nodeInfo, &coreConf.InboundDetourConfig{}); err == nil {
		t.Fatal("expected unsupported ArtX underlay to fail")
	}
}

// nativeAnyTLSDefaultScheme mirrors xray-core proxy/anytls defaultPaddingScheme.
// ArtX profiles must diverge from it so the on-wire packet-size distribution
// (and padding-scheme md5) is no longer identical to native AnyTLS.
var nativeAnyTLSDefaultScheme = []string{
	"stop=8",
	"0=30-30",
	"1=100-400",
	"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
	"3=9-9,500-1000",
	"4=500-1000",
	"5=500-1000",
	"6=500-1000",
	"7=500-1000",
}

func inboundPaddingScheme(t *testing.T, inbound *coreConf.InboundDetourConfig) []string {
	t.Helper()
	if inbound.Settings == nil {
		t.Fatal("expected ArtX to configure underlay settings")
	}
	var settings struct {
		PaddingScheme []string `json:"paddingScheme"`
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal underlay settings failed: %v", err)
	}
	return settings.PaddingScheme
}

// TestBuildArtXDerivesPaddingFromProfile is the P1#4 isolation guarantee:
// when the panel does not pin an explicit padding scheme, each ArtX profile
// must resolve to its own scheme that differs from native AnyTLS.
func TestBuildArtXDerivesPaddingFromProfile(t *testing.T) {
	nativeJoined := strings.Join(nativeAnyTLSDefaultScheme, "\n")

	for _, profile := range []string{"balanced", "web", "media", "realtime"} {
		nodeInfo := &panel.NodeInfo{
			Type: "artx",
			ArtX: &panel.ArtXNode{
				Underlay: "anytls",
				Profile:  profile,
			},
		}
		inbound := &coreConf.InboundDetourConfig{}
		if err := buildArtX(nil, nodeInfo, inbound); err != nil {
			t.Fatalf("profile %q: buildArtX returned error: %v", profile, err)
		}

		got := strings.Join(inboundPaddingScheme(t, inbound), "\n")
		if got == "" {
			t.Fatalf("profile %q: expected a profile-derived padding scheme, got empty", profile)
		}
		if got == nativeJoined {
			t.Fatalf("profile %q: padding scheme is identical to native AnyTLS default; no isolation", profile)
		}
	}
}

// TestBuildArtXRespectsExplicitPaddingOverride keeps operator override intact:
// a non-empty padding scheme from the panel wins over the profile default.
func TestBuildArtXRespectsExplicitPaddingOverride(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Type: "artx",
		ArtX: &panel.ArtXNode{
			Underlay:      "anytls",
			Profile:       "balanced",
			PaddingScheme: []string{"stop=2", "0=11-11"},
		},
	}
	inbound := &coreConf.InboundDetourConfig{}
	if err := buildArtX(nil, nodeInfo, inbound); err != nil {
		t.Fatalf("buildArtX returned error: %v", err)
	}
	if got := strings.Join(inboundPaddingScheme(t, inbound), "\n"); got != "stop=2\n0=11-11" {
		t.Fatalf("expected explicit override to win, got %q", got)
	}
}

// TestArtXProfilePaddingSchemesAreDistinct asserts the four profiles carve out
// four different traffic pictures and none collides with native AnyTLS.
func TestArtXProfilePaddingSchemesAreDistinct(t *testing.T) {
	seen := map[string]string{
		strings.Join(nativeAnyTLSDefaultScheme, "\n"): "native-anytls",
	}
	for _, profile := range []string{"balanced", "web", "media", "realtime"} {
		scheme := strings.Join(artXProfilePaddingScheme(profile), "\n")
		if scheme == "" {
			t.Fatalf("profile %q resolved to empty scheme", profile)
		}
		if other, ok := seen[scheme]; ok {
			t.Fatalf("profile %q padding scheme collides with %q", profile, other)
		}
		seen[scheme] = profile
	}
}

// TestArtXUnknownProfileFallsBackToBalanced is defense in depth: X-Board already
// rejects undefined profiles, but N2X must still produce a valid scheme.
func TestArtXUnknownProfileFallsBackToBalanced(t *testing.T) {
	if got, want := strings.Join(artXProfilePaddingScheme("does-not-exist"), "\n"),
		strings.Join(artXProfilePaddingScheme("balanced"), "\n"); got != want {
		t.Fatalf("unknown profile should fall back to balanced, got %q", got)
	}
}

// TestArtXObservationReportsProfileAndPaddingFingerprint is the P1#5 node-side
// observability slice: each ArtX inbound yields a summary carrying the profile,
// underlay and the padding-scheme md5 actually applied, with no secrets.
func TestArtXObservationReportsProfileAndPaddingFingerprint(t *testing.T) {
	node := &panel.ArtXNode{
		Underlay:       "anytls",
		Profile:        "media",
		ProfileVersion: 1,
		Fallback:       panel.ArtXFallback{Enabled: true, Origin: "https://edge.example.com/"},
	}
	obs := newArtXObservation(node)

	if obs.Protocol != "artx" {
		t.Fatalf("expected protocol artx, got %q", obs.Protocol)
	}
	if obs.Underlay != "anytls" {
		t.Fatalf("expected underlay anytls, got %q", obs.Underlay)
	}
	if obs.Profile != "media" {
		t.Fatalf("expected profile media, got %q", obs.Profile)
	}
	if obs.ProfileVersion != 1 {
		t.Fatalf("expected profile_version 1, got %d", obs.ProfileVersion)
	}
	if obs.PaddingSource != "profile" {
		t.Fatalf("expected padding source profile, got %q", obs.PaddingSource)
	}
	if !obs.FallbackEnabled {
		t.Fatal("expected fallback_enabled true")
	}
	want := paddingSchemeMD5(artXProfilePaddingScheme("media"))
	if obs.PaddingSchemeMD5 != want {
		t.Fatalf("padding md5 mismatch: got %q want %q", obs.PaddingSchemeMD5, want)
	}
}

// TestArtXObservationFingerprintMatchesAnyTLSIdentity guards that the logged md5
// equals the identity the anytls padding layer negotiates on the wire, i.e.
// md5 over the scheme lines joined by "\n" (see xray anytls padding.go).
func TestArtXObservationFingerprintMatchesAnyTLSIdentity(t *testing.T) {
	scheme := artXProfilePaddingScheme("balanced")
	got := paddingSchemeMD5(scheme)
	want := fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(scheme, "\n"))))
	if got != want {
		t.Fatalf("padding md5 must match anytls identity: got %q want %q", got, want)
	}
}

// TestArtXObservationDivergesFromNativeAnyTLS is the observability proof that
// P1#4 took effect: every profile's padding fingerprint differs from the native
// AnyTLS default fingerprint.
func TestArtXObservationDivergesFromNativeAnyTLS(t *testing.T) {
	nativeMD5 := paddingSchemeMD5(nativeAnyTLSDefaultScheme)
	for _, profile := range []string{"balanced", "web", "media", "realtime"} {
		if got := paddingSchemeMD5(artXProfilePaddingScheme(profile)); got == nativeMD5 {
			t.Fatalf("profile %q padding fingerprint equals native AnyTLS (%s)", profile, nativeMD5)
		}
	}
}

// TestArtXObservationMarksExplicitOverride records when an operator pinned a
// padding scheme, and the fingerprint tracks that override rather than the
// profile default.
func TestArtXObservationMarksExplicitOverride(t *testing.T) {
	override := []string{"stop=2", "0=11-11"}
	node := &panel.ArtXNode{
		Underlay:      "anytls",
		Profile:       "balanced",
		PaddingScheme: override,
	}
	obs := newArtXObservation(node)
	if obs.PaddingSource != "override" {
		t.Fatalf("expected padding source override, got %q", obs.PaddingSource)
	}
	if obs.PaddingSchemeMD5 != paddingSchemeMD5(override) {
		t.Fatal("override fingerprint should track the pinned scheme")
	}
}
