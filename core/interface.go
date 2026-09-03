package core

import (
	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

// RuntimeStatsProvider exposes protocol-owned process counters without making
// them part of the mutation-oriented Core interface.
type RuntimeStatsProvider interface {
	RuntimeStats(tag string) RuntimeStats
}

type RuntimeStats struct {
	ActiveConnections uint64
	TotalConnections  uint64
	ArtX              *ArtXRuntimeStats
}

// ArtXFlowControlScaleBuckets is the length of the per-scale negotiation
// histogram: one bucket per window scale in [0, MaxWindowScale]. It mirrors
// artx.MaxWindowScale+1 in the core, restated here so this package stays free
// of a core dependency.
const ArtXFlowControlScaleBuckets = 5

// ArtXFlowControlProvider takes the two inputs the ArtX auto flow-control
// policy cannot observe for itself: the per-user plan rates, which only the
// panel knows, and host utilisation, which only the agent samples. Cores that
// do not carry ArtX simply do not implement it.
type ArtXFlowControlProvider interface {
	// SetArtXUserRates replaces one node tag's slice of the process-wide
	// email → bytes-per-second table. Keys must match the Email the core
	// assigned to each ArtX user.
	SetArtXUserRates(tag string, rates map[string]uint64)
	// ClearArtXUserRates drops a node tag's slice of that table.
	ClearArtXUserRates(tag string)
	// ObserveArtXHostPressure feeds one host utilisation sample, both
	// values percentages in [0, 100], to the window-ceiling governor.
	ObserveArtXHostPressure(cpuPercent, memoryPercent float64)
}

type ArtXRuntimeStats struct {
	AuthenticationSuccess uint64
	AuthenticationFailure uint64
	ReplayRejected        uint64
	FallbackHits          uint64
	FallbackErrors        uint64
	FlowControlNegotiated uint64
	// FlowControlScales counts negotiations per selected window scale,
	// indexed by the scale itself. Index 0 is the legacy window.
	FlowControlScales [ArtXFlowControlScaleBuckets]uint64
	// FlowControlPressureCeiling is the ceiling the host pressure governor
	// applied to the most recent negotiation — a gauge, not a total.
	FlowControlPressureCeiling uint64
	// FlowControlAutoFallback counts auto-policy negotiations that could
	// not read an RTT and fell back to the node maximum.
	FlowControlAutoFallback uint64
	RequestedUDPMode        string
	ActiveUDPMode           string
	NativeListenerReady     bool
	NativeActive            uint64
	NativeAccepted          uint64
	NativeRejected          uint64
	NativeDatagramsUp       uint64
	NativeDatagramsDown     uint64
	NativeBytesUp           uint64
	NativeBytesDown         uint64
	NativeTransportErrors   uint64
	NativeTargetErrors      uint64
	NativeCleanupFailures   uint64
	NativeCleanupMillis     uint64
	LastErrorCode           string
	LastErrorUnix           int64
}

type Core interface {
	Start() error
	Close() error
	AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error
	DelNode(tag string) error
	AddUsers(p *AddUsersParams) (added int, err error)
	GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error)
	DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error
	Protocols() []string
	Type() string
}
