package node

import (
	"context"
	"reflect"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	log "github.com/sirupsen/logrus"
)

const (
	// artXPressureSampleInterval is how often the host utilisation governor
	// is fed. The governor smooths over its own multi-second windows, so
	// sampling faster buys nothing and costs a blocking CPU probe.
	artXPressureSampleInterval = 10 * time.Second
	// artXPressureCPUWindow is the busy-time window for one CPU probe. It
	// blocks the sampler goroutine only — the status and metrics reports
	// keep their own probes, so nothing is stacked onto the report path.
	artXPressureCPUWindow = 500 * time.Millisecond
	// artXMbpsToBytesPerSecond mirrors limiter/limiter.go, which shapes a
	// user with `limit * 1000000 / 8`. The auto policy has to size windows
	// for the rate the bucket actually allows, so the two must agree.
	artXMbpsToBytesPerSecond = 1000000 / 8
)

// artXUserRateBytesPerSecond converts the panel's Mbps figures into the
// bytes-per-second the core expects. Both limits are optional: 0 (or anything
// negative, which the panel should never send) means "no cap at this level",
// and when both levels cap, the tighter one wins — the same min-of-non-zero
// rule limiter.determineSpeedLimit applies.
func artXUserRateBytesPerSecond(nodeSpeedLimit, userSpeedLimit int) uint64 {
	if nodeSpeedLimit < 0 {
		nodeSpeedLimit = 0
	}
	if userSpeedLimit < 0 {
		userSpeedLimit = 0
	}
	effective := nodeSpeedLimit
	if effective == 0 || (userSpeedLimit != 0 && userSpeedLimit < effective) {
		effective = userSpeedLimit
	}
	if effective == 0 {
		return 0
	}
	return uint64(effective) * artXMbpsToBytesPerSecond
}

// buildArtXUserRates renders an immutable email → bytes-per-second table for
// one node tag. The key must be byte-identical to the Email the core assigned
// each ArtX user in core/xray/artxwire.go's buildArtXWireUsers, which is why
// both sides call format.UserTag rather than formatting the pair inline.
func buildArtXUserRates(tag string, nodeSpeedLimit int, users []panel.UserInfo) map[string]uint64 {
	rates := make(map[string]uint64, len(users))
	for i := range users {
		rates[format.UserTag(tag, users[i].Uuid)] =
			artXUserRateBytesPerSecond(nodeSpeedLimit, users[i].SpeedLimit)
	}
	return rates
}

// artXFlowControlProvider returns the core's flow-control hook, or nil when
// this node does not run native ArtX wire or the core does not carry ArtX.
func (c *Controller) artXFlowControlProvider(info *panel.NodeInfo) vCore.ArtXFlowControlProvider {
	if c == nil || !usesNativeArtXWire(info) {
		return nil
	}
	provider, _ := c.server.(vCore.ArtXFlowControlProvider)
	return provider
}

// artXFlowControlOnlyChange reports whether the panel's new node body differs
// from the running one in nothing but the ArtX flow-control tier.
//
// That case is worth singling out because the generic reload path answers any
// change to a node body with DelNode + AddNode, which unbinds the listener and
// kills every session on it. An operator flipping a tier in the admin panel has
// no reason to expect the node to drop — but until the tier became mutable at
// runtime, dropping it was the only way to apply one.
//
// The comparison is deliberately exact: anything else that moved, however
// small, sends the node down the full reload path where it belongs.
func artXFlowControlOnlyChange(old, updated *panel.NodeInfo) bool {
	if !usesNativeArtXWire(old) || !usesNativeArtXWire(updated) {
		return false
	}
	if old.ArtX.FlowControl == updated.ArtX.FlowControl {
		return false
	}
	return reflect.DeepEqual(maskArtXFlowControl(old), maskArtXFlowControl(updated))
}

// maskArtXFlowControl copies a node body with the flow-control tier blanked, so
// the two bodies can be compared on everything except the field under test.
// Both copies are shallow apart from the ArtX block, which is the only one
// being rewritten; the originals are left untouched.
func maskArtXFlowControl(info *panel.NodeInfo) *panel.NodeInfo {
	masked := *info
	artX := *info.ArtX
	artX.FlowControl = ""
	masked.ArtX = &artX
	return &masked
}

// retierArtXFlowControl applies a new tier to the running inbound, reporting
// whether it took. A false answer is not fatal: the caller falls back to the
// full reload, which rebuilds the inbound with the new tier baked in.
func (c *Controller) retierArtXFlowControl(info *panel.NodeInfo) bool {
	provider := c.artXFlowControlProvider(info)
	if provider == nil {
		return false
	}
	if err := provider.SetArtXFlowControl(c.tag, info.ArtX); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).
			Warn("Retier ArtX flow control in place failed, falling back to a full reload")
		return false
	}
	log.WithFields(log.Fields{
		"tag":          c.tag,
		"flow_control": info.ArtX.FlowControl,
	}).Info("ArtX flow control retiered in place, node kept online")
	return true
}

// publishArtXUserRates hands the core the plan rate of every user on this node
// so the auto policy can size windows per user. Safe to call on every panel
// pull: the table is rebuilt from scratch and swapped atomically.
func (c *Controller) publishArtXUserRates() {
	provider := c.artXFlowControlProvider(c.info)
	if provider == nil {
		return
	}
	provider.SetArtXUserRates(c.tag, buildArtXUserRates(c.tag, c.LimitConfig.SpeedLimit, c.userList))
}

// clearArtXUserRates releases this node's slice of the shared table on
// shutdown.
func (c *Controller) clearArtXUserRates() {
	c.clearArtXUserRatesForTag(c.tag)
}

// clearArtXUserRatesForTag releases one tag's slice. Unlike the publish path
// it does not check the node type: a node that has just stopped being ArtX
// wire — or been renamed — still owns a slice published under its old identity,
// and that slice has to go. Clearing an absent tag is a no-op.
func (c *Controller) clearArtXUserRatesForTag(tag string) {
	provider, _ := c.server.(vCore.ArtXFlowControlProvider)
	if provider == nil {
		return
	}
	provider.ClearArtXUserRates(tag)
}

// startArtXPressureSampler begins feeding host utilisation to the window
// ceiling governor. It is a no-op for nodes that do not run native ArtX wire,
// so a node serving another protocol never pays for the probe. Calling it
// while a sampler is already running is a no-op too.
func (c *Controller) startArtXPressureSampler(info *panel.NodeInfo) {
	provider := c.artXFlowControlProvider(info)
	if provider == nil || c.artXPressureCancel != nil {
		return
	}
	c.configureArtXWindowBudget(provider)
	ctx, cancel := context.WithCancel(context.Background())
	c.artXPressureCancel = cancel
	go runArtXPressureSampler(ctx, artXPressureSampleInterval, sampleHostPressure, provider.ObserveArtXHostPressure)
	log.WithField("tag", c.tag).Info("Start ArtX host pressure sampling")
}

// configureArtXWindowBudget installs this node's window budget policy on the
// core before the first probe can land, so the very first connection is
// negotiated against the configured budget rather than the default one.
//
// The budget is a host-level resource shared by every ArtX inbound in the
// process, so the policy is process-wide: with two native ArtX wire nodes on
// one host, the last sampler to start wins. Give them the same block, or set
// it on neither and take the default.
func (c *Controller) configureArtXWindowBudget(provider vCore.ArtXFlowControlProvider) {
	var policy vCore.ArtXWindowBudgetPolicy
	if c.Options != nil && c.ArtXOptions != nil {
		policy.SharePercent = c.ArtXOptions.WindowBudgetSharePercent
		policy.ReservePercent = c.ArtXOptions.WindowBudgetReservePercent
	}
	if err := provider.ConfigureArtXWindowBudget(policy); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).
			Warn("Ignore out-of-range ArtX window budget value, using the core default instead")
	}
	if policy == (vCore.ArtXWindowBudgetPolicy{}) {
		return
	}
	log.WithFields(log.Fields{
		"tag":             c.tag,
		"share_percent":   policy.SharePercent,
		"reserve_percent": policy.ReservePercent,
	}).Info("Apply configured ArtX window budget")
}

func (c *Controller) stopArtXPressureSampler() {
	if c.artXPressureCancel == nil {
		return
	}
	c.artXPressureCancel()
	c.artXPressureCancel = nil
}

// runArtXPressureSampler drives one probe per interval until the context is
// cancelled. The probe and the sink are parameters so the loop can be tested
// without waiting on real hardware or a real interval.
func runArtXPressureSampler(
	ctx context.Context,
	interval time.Duration,
	sample func() (vCore.ArtXHostPressureSample, bool),
	observe func(vCore.ArtXHostPressureSample),
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A failed probe is dropped rather than reported as zero
			// load: zero would read as an idle host and let the
			// governor raise the ceiling on no evidence.
			if observation, ok := sample(); ok {
				observe(observation)
			}
		}
	}
}

// sampleHostPressure reads one host utilisation observation. A sample counts
// as usable if either probe succeeded; the governor judges the ladder on
// whichever percentage is higher, so a missing half reported as 0 cannot
// inflate the result.
//
// The memory probe also reports Total and Available in bytes, which feed the
// core's per-connection window budget. Available — not Free — is the right
// figure: reclaimable cache is memory ArtX may legitimately spend a window on.
// They stay zero when the probe fails, and zero is exactly how the core spells
// "memory size unknown, leave the budget clamp inactive".
func sampleHostPressure() (vCore.ArtXHostPressureSample, bool) {
	var sample vCore.ArtXHostPressureSample
	ok := false
	if percents, err := cpu.Percent(artXPressureCPUWindow, false); err == nil && len(percents) > 0 {
		sample.CPUPercent = clampPercent(percents[0])
		ok = true
	} else if err != nil {
		log.WithField("err", err).Debug("sample artx cpu pressure failed")
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		sample.MemoryPercent = clampPercent(vm.UsedPercent)
		sample.MemoryTotalBytes = vm.Total
		sample.MemoryAvailableBytes = vm.Available
		ok = true
	} else {
		log.WithField("err", err).Debug("sample artx memory pressure failed")
	}
	return sample, ok
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
