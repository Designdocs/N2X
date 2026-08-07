package core

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

type selectorRuntimeStatsProvider struct {
	Core
	coreType  string
	protocols []string
	addedTag  string
	tag       string
	stats     RuntimeStats
}

type selectorCoreWithoutStats struct {
	Core
}

func (p *selectorRuntimeStatsProvider) AddNode(
	tag string,
	_ *panel.NodeInfo,
	_ *conf.Options,
) error {
	p.addedTag = tag
	return nil
}

func (p *selectorRuntimeStatsProvider) Type() string {
	if p.coreType == "" {
		return "xray"
	}
	return p.coreType
}

func (p *selectorRuntimeStatsProvider) Protocols() []string {
	if p.protocols == nil {
		return []string{"artx"}
	}
	return p.protocols
}

func (p *selectorRuntimeStatsProvider) RuntimeStats(tag string) RuntimeStats {
	p.tag = tag
	return p.stats
}

func TestSelectorRuntimeStatsForwardsToNodeCore(t *testing.T) {
	primary := &selectorRuntimeStatsProvider{
		stats: RuntimeStats{
			ActiveConnections: 2,
			TotalConnections:  7,
			ArtX: &ArtXRuntimeStats{
				AuthenticationSuccess: 5,
				FallbackHits:          1,
			},
		},
	}
	secondary := &selectorRuntimeStatsProvider{
		stats: RuntimeStats{TotalConnections: 11},
	}
	selector := &Selector{cores: map[string]Core{
		"primary":   primary,
		"secondary": secondary,
	}}
	if err := selector.AddNode(
		"artx-canary",
		&panel.NodeInfo{Type: "artx"},
		&conf.Options{Core: "xray", CoreName: "primary"},
	); err != nil {
		t.Fatalf("AddNode(primary): %v", err)
	}
	if err := selector.AddNode(
		"artx-secondary",
		&panel.NodeInfo{Type: "artx"},
		&conf.Options{Core: "xray", CoreName: "secondary"},
	); err != nil {
		t.Fatalf("AddNode(secondary): %v", err)
	}

	got := selector.RuntimeStats("artx-canary")

	if primary.addedTag != "artx-canary" || secondary.addedTag != "artx-secondary" {
		t.Fatalf("added tags = %q, %q", primary.addedTag, secondary.addedTag)
	}
	if primary.tag != "artx-canary" {
		t.Fatalf("forwarded tag = %q, want artx-canary", primary.tag)
	}
	if got.ActiveConnections != 2 || got.TotalConnections != 7 {
		t.Fatalf("connection stats = %#v", got)
	}
	if got.ArtX == nil || got.ArtX.AuthenticationSuccess != 5 || got.ArtX.FallbackHits != 1 {
		t.Fatalf("ArtX stats = %#v", got.ArtX)
	}
	if secondaryGot := selector.RuntimeStats("artx-secondary"); secondaryGot.TotalConnections != 11 {
		t.Fatalf("secondary connection stats = %#v", secondaryGot)
	}
}

func TestSelectorRuntimeStatsReturnsZeroWithoutProvider(t *testing.T) {
	selector := &Selector{}
	selector.nodes.Store("unsupported", &selectorCoreWithoutStats{})

	for _, tag := range []string{"missing", "unsupported"} {
		if got := selector.RuntimeStats(tag); got != (RuntimeStats{}) {
			t.Fatalf("RuntimeStats(%q) = %#v, want zero value", tag, got)
		}
	}
}

// newAnyTLSSelector builds a selector holding an xray core and a sing core
// that both advertise anytls, which is the coexistence case AnyTLS relies on.
func newAnyTLSSelector() (*Selector, *selectorRuntimeStatsProvider, *selectorRuntimeStatsProvider) {
	xray := &selectorRuntimeStatsProvider{
		coreType:  "xray",
		protocols: []string{"vless", "anytls", "artx"},
	}
	sing := &selectorRuntimeStatsProvider{
		coreType:  "sing",
		protocols: []string{"vless", "anytls", "hysteria2", "tuic", "shadowtls", "naive"},
	}
	// Keyed the way NewSelector keys unnamed cores: by type.
	return &Selector{cores: map[string]Core{"xray": xray, "sing": sing}}, xray, sing
}

func TestSelectorAnyTLSDefaultsToXrayDeterministically(t *testing.T) {
	// Map iteration order is randomised, so a single pass can pass by luck.
	// Rebuild the selector each round to resample the ordering.
	for i := 0; i < 50; i++ {
		selector, xray, sing := newAnyTLSSelector()
		if err := selector.AddNode("anytls-node", &panel.NodeInfo{Type: "anytls"}, &conf.Options{
			Core: "xray",
		}); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		if xray.addedTag != "anytls-node" {
			t.Fatalf("round %d: xray core did not receive the node", i)
		}
		if sing.addedTag != "" {
			t.Fatalf("round %d: sing core received the node", i)
		}
	}
}

func TestSelectorAnyTLSHonoursExplicitCore(t *testing.T) {
	for _, tc := range []struct {
		name     string
		options  *conf.Options
		wantSing bool
	}{
		{name: "pin sing by type", options: &conf.Options{Core: "sing"}, wantSing: true},
		{name: "pin xray by type", options: &conf.Options{Core: "xray"}},
		{name: "pin sing by name", options: &conf.Options{CoreName: "sing"}, wantSing: true},
		{name: "pin xray by name", options: &conf.Options{CoreName: "xray"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, xray, sing := newAnyTLSSelector()
			if err := selector.AddNode("anytls-node", &panel.NodeInfo{Type: "anytls"}, tc.options); err != nil {
				t.Fatalf("AddNode: %v", err)
			}
			gotSing := sing.addedTag == "anytls-node"
			gotXray := xray.addedTag == "anytls-node"
			if gotSing == gotXray {
				t.Fatalf("exactly one core should serve the node, sing=%v xray=%v", gotSing, gotXray)
			}
			if gotSing != tc.wantSing {
				t.Fatalf("routed to sing = %v, want %v", gotSing, tc.wantSing)
			}
		})
	}
}

// TestSelectorUnpinnedProtocolPrefersPriorityOrder covers the case where a
// node names no core at all: selection must still be stable.
func TestSelectorUnpinnedProtocolIsStable(t *testing.T) {
	for i := 0; i < 50; i++ {
		selector, xray, sing := newAnyTLSSelector()
		// RawOptions must be valid JSON: the selector re-decodes the options
		// once it has resolved the core.
		if err := selector.AddNode("anytls-node", &panel.NodeInfo{Type: "anytls"}, &conf.Options{
			RawOptions: []byte(`{}`),
		}); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		if xray.addedTag != "anytls-node" || sing.addedTag != "" {
			t.Fatalf("round %d: unpinned anytls did not default to xray", i)
		}
	}
}

func TestSelectorSingOnlyProtocolsRouteToSing(t *testing.T) {
	for _, nodeType := range []string{"hysteria2", "tuic", "shadowtls", "naive"} {
		t.Run(nodeType, func(t *testing.T) {
			selector, xray, sing := newAnyTLSSelector()
			if err := selector.AddNode(nodeType+"-node", &panel.NodeInfo{Type: nodeType}, &conf.Options{
				RawOptions: []byte(`{}`),
			}); err != nil {
				t.Fatalf("AddNode: %v", err)
			}
			if sing.addedTag != nodeType+"-node" {
				t.Fatalf("%s did not route to the sing core", nodeType)
			}
			if xray.addedTag != "" {
				t.Fatalf("%s reached the xray core", nodeType)
			}
		})
	}
}

func TestSelectorRejectsUnsupportedPin(t *testing.T) {
	selector, _, _ := newAnyTLSSelector()
	// The xray core in this fixture does not advertise hysteria2.
	err := selector.AddNode("hy2", &panel.NodeInfo{Type: "hysteria2"}, &conf.Options{Core: "xray"})
	if err == nil {
		t.Fatal("pinning a core that cannot serve the protocol should fail")
	}

	err = selector.AddNode("hy2", &panel.NodeInfo{Type: "hysteria2"}, &conf.Options{CoreName: "nope"})
	if err == nil {
		t.Fatal("pinning an unknown core name should fail")
	}
}
