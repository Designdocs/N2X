package node

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	vCore "github.com/Designdocs/N2X/core"
)

type runtimeStatsCore struct {
	vCore.Core
	stats vCore.RuntimeStats
}

func (core *runtimeStatsCore) RuntimeStats(string) vCore.RuntimeStats {
	return core.stats
}

func TestApplyProtocolRuntimeStatsUsesArtXCounters(t *testing.T) {
	controller := &Controller{
		server: &runtimeStatsCore{stats: vCore.RuntimeStats{
			ActiveConnections: 3,
			TotalConnections:  21,
			ArtX: &vCore.ArtXRuntimeStats{
				AuthenticationSuccess: 18,
				AuthenticationFailure: 3,
				ReplayRejected:        1,
				FallbackHits:          3,
				FallbackErrors:        1,
			},
		}},
		tag: "artx-canary",
		info: &panel.NodeInfo{
			Type: "artx",
			ArtX: &panel.ArtXNode{Underlay: "artx-wire"},
		},
	}
	metrics := &panel.NodeMetrics{ActiveConnections: 99}

	controller.applyProtocolRuntimeStats(metrics)

	if metrics.ActiveConnections != 3 || metrics.TotalConnections != 21 {
		t.Fatalf("connection metrics = %#v", metrics)
	}
	if metrics.ArtX == nil || metrics.ArtX.AuthenticationSuccess != 18 || metrics.ArtX.FallbackHits != 3 {
		t.Fatalf("ArtX metrics = %#v", metrics.ArtX)
	}
}

func TestApplyProtocolRuntimeStatsLeavesArtXAnyTLSMetricsUntouched(t *testing.T) {
	controller := &Controller{
		server: &runtimeStatsCore{stats: vCore.RuntimeStats{
			ActiveConnections: 1,
			TotalConnections:  2,
		}},
		info: &panel.NodeInfo{
			Type: "artx",
			ArtX: &panel.ArtXNode{Underlay: "anytls"},
		},
	}
	metrics := &panel.NodeMetrics{ActiveConnections: 4, TotalConnections: 8}

	controller.applyProtocolRuntimeStats(metrics)

	if metrics.ActiveConnections != 4 || metrics.TotalConnections != 8 || metrics.ArtX != nil {
		t.Fatalf("ArtX AnyTLS metrics changed: %#v", metrics)
	}
}

func TestApplyProtocolRuntimeStatsLeavesNonArtXMetricsUntouched(t *testing.T) {
	controller := &Controller{
		server: &runtimeStatsCore{},
		info:   &panel.NodeInfo{Type: "anytls"},
	}
	metrics := &panel.NodeMetrics{ActiveConnections: 4, TotalConnections: 8}

	controller.applyProtocolRuntimeStats(metrics)

	if metrics.ActiveConnections != 4 || metrics.TotalConnections != 8 || metrics.ArtX != nil {
		t.Fatalf("non-ArtX metrics changed: %#v", metrics)
	}
}
