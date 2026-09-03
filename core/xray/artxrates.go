package xray

import (
	"sync"
	"sync/atomic"

	vCore "github.com/Designdocs/N2X/core"
	"github.com/xtls/xray-core/proxy/artx"
)

var _ vCore.ArtXFlowControlProvider = (*Xray)(nil)

// artXUserRates is the process-wide plan-rate table the ArtX auto flow-control
// policy reads. It is package state rather than per-Xray state because the
// core's lookup hook is itself process-wide: one agent process runs one core,
// but several node controllers publish into it, each owning one tag.
var artXUserRates artXUserRateTable

// artXUserRateTable maps an ArtX user Email to the plan rate in bytes per
// second, 0 meaning unlimited.
//
// Writes are rare (one panel pull cycle) and reads sit on the connection
// accept path, so the merged view is published as an immutable snapshot behind
// an atomic pointer: a lookup never takes a lock and never observes a
// half-applied update. The mutex guards only the per-tag inputs the merge is
// rebuilt from.
type artXUserRateTable struct {
	mu       sync.Mutex
	perTag   map[string]map[string]uint64
	merged   atomic.Pointer[map[string]uint64]
	installO sync.Once
}

// set replaces one tag's slice of the table wholesale, so users the panel
// dropped stop resolving rather than lingering at their old rate.
func (table *artXUserRateTable) set(tag string, rates map[string]uint64) {
	snapshot := make(map[string]uint64, len(rates))
	for email, rate := range rates {
		snapshot[email] = rate
	}

	table.mu.Lock()
	defer table.mu.Unlock()
	if table.perTag == nil {
		table.perTag = make(map[string]map[string]uint64)
	}
	table.perTag[tag] = snapshot
	table.rebuildLocked()
}

func (table *artXUserRateTable) clear(tag string) {
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.perTag == nil {
		return
	}
	delete(table.perTag, tag)
	table.rebuildLocked()
}

func (table *artXUserRateTable) rebuildLocked() {
	size := 0
	for _, rates := range table.perTag {
		size += len(rates)
	}
	merged := make(map[string]uint64, size)
	for _, rates := range table.perTag {
		for email, rate := range rates {
			merged[email] = rate
		}
	}
	table.merged.Store(&merged)
}

// lookup resolves one user's plan rate. An unknown user reads as 0, which the
// core treats as unlimited — the same answer it would give with no lookup
// installed at all, so a stale or missing table degrades to the default rather
// than to a throttle.
func (table *artXUserRateTable) lookup(userEmail string) uint64 {
	merged := table.merged.Load()
	if merged == nil {
		return 0
	}
	return (*merged)[userEmail]
}

// install publishes this table as the core's shared lookup, once per process.
func (table *artXUserRateTable) install() {
	table.installO.Do(func() {
		artx.SetSharedUserRateLookup(table.lookup)
	})
}

// SetArtXUserRates implements vCore.ArtXFlowControlProvider. The keys must be
// the Email values buildArtXWireUsers assigned, i.e. format.UserTag(tag, uuid).
func (c *Xray) SetArtXUserRates(tag string, rates map[string]uint64) {
	artXUserRates.set(tag, rates)
	artXUserRates.install()
}

// ClearArtXUserRates implements vCore.ArtXFlowControlProvider.
func (c *Xray) ClearArtXUserRates(tag string) {
	artXUserRates.clear(tag)
}

// ObserveArtXHostPressure implements vCore.ArtXFlowControlProvider. The core
// timestamps the sample itself and creates the governor on first use.
func (c *Xray) ObserveArtXHostPressure(cpuPercent, memoryPercent float64) {
	artx.ObserveHostPressure(artx.PressureSample{
		CPUPercent:    cpuPercent,
		MemoryPercent: memoryPercent,
	})
}
