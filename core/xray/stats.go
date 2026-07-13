package xray

import (
	vCore "github.com/Designdocs/N2X/core"
	featurestats "github.com/xtls/xray-core/features/stats"
	artxstats "github.com/xtls/xray-core/proxy/artx"
)

var _ vCore.RuntimeStatsProvider = (*Xray)(nil)

func (c *Xray) RuntimeStats(tag string) vCore.RuntimeStats {
	if c == nil || c.Server == nil {
		return artXRuntimeStats(nil, tag)
	}
	manager, _ := c.Server.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	return artXRuntimeStats(manager, tag)
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
		},
	}
}
