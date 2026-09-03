package node

import (
	"context"
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
	ctx, cancel := context.WithCancel(context.Background())
	c.artXPressureCancel = cancel
	go runArtXPressureSampler(ctx, artXPressureSampleInterval, sampleHostPressure, provider.ObserveArtXHostPressure)
	log.WithField("tag", c.tag).Info("Start ArtX host pressure sampling")
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
	sample func() (cpuPercent, memoryPercent float64, ok bool),
	observe func(cpuPercent, memoryPercent float64),
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
			if cpuPercent, memoryPercent, ok := sample(); ok {
				observe(cpuPercent, memoryPercent)
			}
		}
	}
}

// sampleHostPressure reads one CPU/memory utilisation pair. A sample counts as
// usable if either probe succeeded; the governor judges on whichever value is
// higher, so a missing half reported as 0 cannot inflate the result.
func sampleHostPressure() (cpuPercent, memoryPercent float64, ok bool) {
	if percents, err := cpu.Percent(artXPressureCPUWindow, false); err == nil && len(percents) > 0 {
		cpuPercent = clampPercent(percents[0])
		ok = true
	} else if err != nil {
		log.WithField("err", err).Debug("sample artx cpu pressure failed")
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		memoryPercent = clampPercent(vm.UsedPercent)
		ok = true
	} else {
		log.WithField("err", err).Debug("sample artx memory pressure failed")
	}
	return cpuPercent, memoryPercent, ok
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
