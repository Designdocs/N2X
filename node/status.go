package node

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
	log "github.com/sirupsen/logrus"
)

// processStartTime captures the moment the agent process began so the
// metrics task can report a stable uptime to the panel. It is set once at
// package initialisation; callers must never mutate it.
var processStartTime = time.Now()

// collectNodeStatus samples CPU, memory, swap, and root-disk usage. It returns
// a populated panel.NodeStatus even when individual probes fail — missing
// fields are reported as zero so the panel can still record a heartbeat.
func collectNodeStatus() *panel.NodeStatus {
	status := &panel.NodeStatus{}

	// CPU percent over a short window. Sum across cores is implicit — cpu.Percent
	// with interval and percpu=false returns the overall busy percentage.
	if cpuPercents, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(cpuPercents) > 0 {
		status.Cpu = cpuPercents[0]
	} else if err != nil {
		log.WithField("err", err).Debug("collect cpu percent failed")
	}
	if status.Cpu < 0 {
		status.Cpu = 0
	}
	if status.Cpu > 100 {
		status.Cpu = 100
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		status.Mem.Total = vm.Total
		status.Mem.Used = vm.Used
	} else {
		log.WithField("err", err).Debug("collect virtual memory failed")
	}

	if sm, err := mem.SwapMemory(); err == nil {
		status.Swap.Total = sm.Total
		status.Swap.Used = sm.Used
	} else {
		log.WithField("err", err).Debug("collect swap memory failed")
	}

	if du, err := disk.Usage("/"); err == nil {
		status.Disk.Total = du.Total
		status.Disk.Used = du.Used
	} else {
		log.WithField("err", err).Debug("collect disk usage failed")
	}

	return status
}

// reportNodeStatusTask gathers system metrics and pushes them to the panel.
// Errors are logged but not returned, so the periodic task keeps running.
func (c *Controller) reportNodeStatusTask() error {
	status := collectNodeStatus()
	if err := c.apiClient.ReportNodeStatus(status); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Report node status failed")
		return nil
	}
	log.WithFields(log.Fields{
		"tag":  c.tag,
		"cpu":  status.Cpu,
		"mem":  status.Mem.Used,
		"disk": status.Disk.Used,
	}).Debug("Reported node status")
	return nil
}

// collectNodeMetrics fills the rich runtime payload that X-Board's admin
// popup expects. active_connections is sampled live from the limiter's
// online-IP tracking. Fields we still cannot cheaply observe (total_connections,
// gc/api/ws/limits sub-maps) are left zero — the panel happily renders them as
// "—" rather than failing validation.
//
// Inbound/outbound speeds are derived from the cumulative byte counters fed
// by reportUserTrafficTask: delta bytes / elapsed seconds since the last
// metrics tick. The first invocation seeds the baseline and reports zero
// rate, which matches what the official Xboard-Node does on startup.
func (c *Controller) collectNodeMetrics() *panel.NodeMetrics {
	metrics := &panel.NodeMetrics{
		Uptime:            int64(time.Since(processStartTime).Seconds()),
		Goroutines:        runtime.NumGoroutine(),
		TotalUsers:        len(c.userList),
		ActiveUsers:       c.activeUserCount(),
		ActiveConnections: c.activeConnectionCount(),
		KernelStatus:      true,
	}
	c.applyProtocolRuntimeStats(metrics)

	// per-core CPU snapshot — short window keeps the call non-blocking.
	if perCore, err := cpu.Percent(500*time.Millisecond, true); err == nil {
		metrics.CPUPerCore = perCore
	} else {
		log.WithField("err", err).Debug("collect per-core cpu failed")
	}

	// 1/5/15 minute load averages. Not available on every OS — gopsutil
	// returns an error on platforms like Windows where we just leave it nil.
	// Field shape must match the panel frontend: it reads metrics.load.load5
	// as a named property, *not* an array element.
	if avg, err := load.Avg(); err == nil {
		metrics.Load = &panel.NodeMetricsLoad{
			Load1:  avg.Load1,
			Load5:  avg.Load5,
			Load15: avg.Load15,
		}
	} else {
		log.WithField("err", err).Debug("collect load avg failed")
	}

	// Latest GC pause for the runtime — surfaces as "(Xms)" after the ON
	// kernel_status indicator. ReadGCStats keeps a 1-pause buffer so the
	// most recent value is at index 0.
	var gcStats debug.GCStats
	gcStats.Pause = make([]time.Duration, 1)
	debug.ReadGCStats(&gcStats)
	if len(gcStats.Pause) > 0 && gcStats.Pause[0] > 0 {
		metrics.GC = &panel.NodeMetricsGC{
			LastPauseMs: float64(gcStats.Pause[0].Microseconds()) / 1000.0,
		}
	}

	// Panel API health — counters maintained by resty middleware on the
	// Client. Always emitted (even when both are zero) so the popup
	// renders the row immediately after first sync.
	apiSuccess, apiFailure := c.apiClient.APIStats()
	metrics.API = &panel.NodeMetricsAPI{
		Success: apiSuccess,
		Failure: apiFailure,
	}

	// WebSocket driver state. Only emitted when the operator opted in,
	// otherwise the panel hides the WS row entirely (intentional — keeps
	// pure-HTTP deployments from showing a misleading "WS-ERR").
	if c.apiClient.WebSocketEnabled() {
		metrics.WS = &panel.NodeMetricsWS{
			Enabled:   true,
			Connected: c.apiClient.WebSocketConnected(),
		}
	}

	// Active speed-limit users — drives the destructive "X Limit" row.
	// Reading via the helper avoids exposing UserLimitInfo internals to
	// the node package.
	if c.limiter != nil {
		limited := c.limiter.LimitedUserCount()
		if limited > 0 {
			metrics.SpeedLimiter = &panel.NodeMetricsLimiter{
				HasLimits:    true,
				LimitedUsers: limited,
			}
		}
	}

	// Derive throughput from the running totals fed by the user-traffic
	// task. Snapshot the cumulative counters first to avoid double-counting
	// if reportUserTrafficTask races us between reads.
	currentUp := c.totalUploadBytes.Load()
	currentDown := c.totalDownloadBytes.Load()
	now := time.Now()
	if !c.lastMetricsAt.IsZero() {
		elapsed := now.Sub(c.lastMetricsAt).Seconds()
		if elapsed > 0 {
			deltaUp := currentUp - c.lastMetricsUpload
			deltaDown := currentDown - c.lastMetricsDownload
			if deltaUp > 0 {
				metrics.OutboundSpeed = int64(float64(deltaUp) / elapsed)
			}
			if deltaDown > 0 {
				metrics.InboundSpeed = int64(float64(deltaDown) / elapsed)
			}
		}
	}
	c.lastMetricsUpload = currentUp
	c.lastMetricsDownload = currentDown
	c.lastMetricsAt = now

	return metrics
}

func (c *Controller) applyProtocolRuntimeStats(metrics *panel.NodeMetrics) {
	if metrics == nil || !usesNativeArtXWire(c.info) {
		return
	}
	provider, ok := c.server.(vCore.RuntimeStatsProvider)
	if !ok {
		return
	}
	stats := provider.RuntimeStats(c.tag)
	metrics.ActiveConnections = boundedMetricInt(stats.ActiveConnections)
	metrics.TotalConnections = boundedMetricInt(stats.TotalConnections)
	if stats.ArtX == nil {
		return
	}
	metrics.ArtX = &panel.NodeMetricsArtX{
		AuthenticationSuccess: boundedMetricInt(stats.ArtX.AuthenticationSuccess),
		AuthenticationFailure: boundedMetricInt(stats.ArtX.AuthenticationFailure),
		ReplayRejected:        boundedMetricInt(stats.ArtX.ReplayRejected),
		FallbackHits:          boundedMetricInt(stats.ArtX.FallbackHits),
		FallbackErrors:        boundedMetricInt(stats.ArtX.FallbackErrors),
		RequestedUDPMode:      stats.ArtX.RequestedUDPMode,
		ActiveUDPMode:         stats.ArtX.ActiveUDPMode,
		NativeListenerReady:   stats.ArtX.NativeListenerReady,
		NativeActive:          boundedMetricInt(stats.ArtX.NativeActive),
		NativeAccepted:        boundedMetricInt(stats.ArtX.NativeAccepted),
		NativeRejected:        boundedMetricInt(stats.ArtX.NativeRejected),
		NativeDatagramsUp:     boundedMetricInt(stats.ArtX.NativeDatagramsUp),
		NativeDatagramsDown:   boundedMetricInt(stats.ArtX.NativeDatagramsDown),
		NativeBytesUp:         boundedMetricInt(stats.ArtX.NativeBytesUp),
		NativeBytesDown:       boundedMetricInt(stats.ArtX.NativeBytesDown),
		NativeTransportErrors: boundedMetricInt(stats.ArtX.NativeTransportErrors),
		NativeTargetErrors:    boundedMetricInt(stats.ArtX.NativeTargetErrors),
		NativeCleanupFailures: boundedMetricInt(stats.ArtX.NativeCleanupFailures),
		NativeCleanupMillis:   boundedMetricInt(stats.ArtX.NativeCleanupMillis),
		LastErrorCode:         stats.ArtX.LastErrorCode,
		LastErrorUnix:         stats.ArtX.LastErrorUnix,
	}
	if current, err := process.NewProcess(int32(os.Getpid())); err == nil {
		if times, timesErr := current.Times(); timesErr == nil {
			metrics.ArtX.ProcessCPUSeconds = times.Total()
		}
		if memory, memoryErr := current.MemoryInfo(); memoryErr == nil {
			metrics.ArtX.ProcessRSSBytes = memory.RSS
		}
	}
}

func usesNativeArtXWire(info *panel.NodeInfo) bool {
	return info != nil &&
		info.Type == "artx" &&
		info.ArtX != nil &&
		strings.EqualFold(strings.TrimSpace(info.ArtX.Underlay), "artx-wire")
}

func boundedMetricInt(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}

// reportNodeMetricsTask pushes the rich metrics payload to the panel and
// keeps the popup populated. Like the status task it never propagates errors
// so a transient panel outage cannot tear down the periodic loop.
func (c *Controller) reportNodeMetricsTask() error {
	metrics := c.collectNodeMetrics()
	if err := c.apiClient.ReportNodeMetrics(metrics); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Report node metrics failed")
		return nil
	}
	log.WithFields(log.Fields{
		"tag":         c.tag,
		"uptime":      metrics.Uptime,
		"goroutines":  metrics.Goroutines,
		"total_users": metrics.TotalUsers,
		"in_bps":      metrics.InboundSpeed,
		"out_bps":     metrics.OutboundSpeed,
	}).Debug("Reported node metrics")
	return nil
}
