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

type ArtXRuntimeStats struct {
	AuthenticationSuccess uint64
	AuthenticationFailure uint64
	ReplayRejected        uint64
	FallbackHits          uint64
	FallbackErrors        uint64
	RequestedUDPMode      string
	ActiveUDPMode         string
	NativeListenerReady   bool
	NativeActive          uint64
	NativeAccepted        uint64
	NativeRejected        uint64
	NativeDatagramsUp     uint64
	NativeDatagramsDown   uint64
	NativeBytesUp         uint64
	NativeBytesDown       uint64
	NativeTransportErrors uint64
	NativeTargetErrors    uint64
	NativeCleanupFailures uint64
	NativeCleanupMillis   uint64
	LastErrorCode         string
	LastErrorUnix         int64
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
