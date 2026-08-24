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
				FlowControlNegotiated: 5,
				RequestedUDPMode:      "native",
				ActiveUDPMode:         "native",
				NativeListenerReady:   true,
				NativeActive:          2,
				NativeAccepted:        18,
				NativeRejected:        3,
				NativeDatagramsUp:     200,
				NativeDatagramsDown:   199,
				NativeBytesUp:         4096,
				NativeBytesDown:       3072,
				NativeTransportErrors: 1,
				NativeTargetErrors:    2,
				NativeCleanupFailures: 0,
				NativeCleanupMillis:   33,
				LastErrorCode:         "native_target_rejected",
				LastErrorUnix:         1785667200,
			},
		}},
		tag: "artx-canary",
		info: &panel.NodeInfo{
			Type: "artx",
			ArtX: &panel.ArtXNode{
				Underlay:    "artx-wire",
				FlowControl: panel.ArtXFlowControlMediumLatency,
			},
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
	if metrics.ArtX.ConfiguredFlowControl != panel.ArtXFlowControlMediumLatency || metrics.ArtX.MaxWindowScale != 3 || metrics.ArtX.FlowControlNegotiated != 5 {
		t.Fatalf("ArtX flow-control metrics = %#v", metrics.ArtX)
	}
	if metrics.ArtX.RequestedUDPMode != "native" || metrics.ArtX.ActiveUDPMode != "native" ||
		!metrics.ArtX.NativeListenerReady || metrics.ArtX.NativeActive != 2 ||
		metrics.ArtX.NativeAccepted != 18 || metrics.ArtX.NativeRejected != 3 ||
		metrics.ArtX.NativeCleanupMillis != 33 || metrics.ArtX.LastErrorCode != "native_target_rejected" ||
		metrics.ArtX.LastErrorUnix != 1785667200 {
		t.Fatalf("native UDP metrics = %#v", metrics.ArtX)
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
