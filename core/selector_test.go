package core

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

type selectorRuntimeStatsProvider struct {
	Core
	addedTag string
	tag      string
	stats    RuntimeStats
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
