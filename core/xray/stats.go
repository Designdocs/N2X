package xray

import (
	vCore "github.com/Designdocs/N2X/core"
	featurestats "github.com/xtls/xray-core/features/stats"
	artxstats "github.com/xtls/xray-core/proxy/artx"
)

var _ vCore.RuntimeStatsProvider = (*Xray)(nil)

func (c *Xray) RuntimeStats(tag string) vCore.RuntimeStats {
	if c == nil {
		return artXRuntimeStats(nil, tag)
	}
	var manager featurestats.Manager
	if c.Server != nil {
		manager, _ = c.Server.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	}
	result := artXRuntimeStats(manager, tag)
	state := c.nativeUDPStatus(tag)
	result.ArtX.RequestedUDPMode = state.RequestedMode
	result.ArtX.ActiveUDPMode = state.ActiveMode
	result.ArtX.NativeListenerReady = state.ListenerReady
	result.ArtX.NativeCleanupFailures = state.CleanupFailure
	result.ArtX.NativeCleanupMillis = state.CleanupMillis
	result.ArtX.LastErrorCode = state.LastErrorCode
	result.ArtX.LastErrorUnix = state.LastErrorUnix
	return result
}

func artXRuntimeStats(manager featurestats.Manager, tag string) vCore.RuntimeStats {
	stats := artxstats.RuntimeStatsFromManager(manager, tag)
	return vCore.RuntimeStats{
		ActiveConnections: stats.ActiveConnections,
		TotalConnections:  stats.TotalConnections,
		ArtX: &vCore.ArtXRuntimeStats{
			AuthenticationSuccess: stats.AuthenticationSuccess,
			AuthenticationFailure: stats.AuthenticationFailure,
			ReplayRejected:        stats.ReplayRejected,
			FallbackHits:          stats.FallbackHits,
			FallbackErrors:        stats.FallbackErrors,
			FlowControlNegotiated: stats.FlowControlNegotiated,
			// The core's histogram is artx.MaxWindowScale+1 long and vCore
			// restates that width as ArtXFlowControlScaleBuckets. Copying
			// element-wise makes a future core-side widening a compile
			// error here rather than a silently truncated report.
			FlowControlScales: [vCore.ArtXFlowControlScaleBuckets]uint64{
				stats.FlowControlScales[0],
				stats.FlowControlScales[1],
				stats.FlowControlScales[2],
				stats.FlowControlScales[3],
				stats.FlowControlScales[4],
			},
			FlowControlPressureCeiling: stats.FlowControlPressureCeiling,
			FlowControlAutoFallback:    stats.FlowControlAutoFallback,
			NativeActive:               stats.NativeActive,
			NativeAccepted:             stats.NativeAccepted,
			NativeRejected:             stats.NativeRejected,
			NativeDatagramsUp:          stats.NativeDatagramsUp,
			NativeDatagramsDown:        stats.NativeDatagramsDown,
			NativeBytesUp:              stats.NativeBytesUp,
			NativeBytesDown:            stats.NativeBytesDown,
			NativeTransportErrors:      stats.NativeTransportErrors,
			NativeTargetErrors:         stats.NativeTargetErrors,
		},
	}
}
