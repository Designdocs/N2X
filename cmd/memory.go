package cmd

import (
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/Designdocs/N2X/conf"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
	log "github.com/sirupsen/logrus"
)

const (
	memoryCheckInterval   = 5 * time.Second
	memoryShutdownTimeout = 10 * time.Second
)

type memoryPressure struct {
	total, available uint64
	percent          int
}

func (*memoryPressure) Error() string {
	return "memory pressure threshold reached; exiting for service manager restart"
}

type memoryGuard struct {
	restartPercent atomic.Int64
	initialLimit   int64
	explicitLimit  bool
	sample         func() (total, available uint64, err error)
}

func newMemoryGuard() *memoryGuard {
	return &memoryGuard{
		initialLimit:  debug.SetMemoryLimit(-1),
		explicitLimit: os.Getenv("GOMEMLIMIT") != "",
		sample: func() (uint64, uint64, error) {
			vm, err := mem.VirtualMemory()
			if err != nil {
				return 0, 0, err
			}
			if vm.Total == 0 || vm.Available > vm.Total {
				return 0, 0, errors.New("invalid host memory sample")
			}
			return vm.Total, vm.Available, nil
		},
	}
}

func (g *memoryGuard) configure(options conf.MemoryConfig) {
	g.restartPercent.Store(int64(options.RestartPercent))
	// An explicit operator limit takes precedence over the automatic budget.
	if g.explicitLimit {
		return
	}
	if os.Getenv("GOMEMLIMIT") != "" {
		log.Warn("GOMEMLIMIT loaded after process startup is ignored by Go; use the service environment or Memory.SoftLimitPercent")
	}
	if options.SoftLimitPercent == 0 {
		debug.SetMemoryLimit(g.initialLimit)
		return
	}
	total, _, err := g.sample()
	if err != nil {
		log.WithError(err).Warn("Cannot set automatic Go memory limit")
		return
	}
	limit := int64(float64(total) * float64(options.SoftLimitPercent) / 100)
	if limit <= 0 {
		return
	}
	debug.SetMemoryLimit(limit)
	log.WithFields(log.Fields{"bytes": limit, "percent": options.SoftLimitPercent}).Info("Go soft memory limit configured")
}

func memoryRestartRequired(total, available uint64, percent int) bool {
	if percent <= 0 || total == 0 || available > total {
		return false
	}
	return float64(total-available)*100/float64(total) >= float64(percent)
}

func (g *memoryGuard) wait(signals <-chan os.Signal) error {
	ticker := time.NewTicker(memoryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-signals:
			return nil
		case <-ticker.C:
			percent := int(g.restartPercent.Load())
			if percent == 0 {
				continue
			}
			total, available, err := g.sample()
			if err != nil {
				log.WithError(err).Warn("Memory guard sample failed")
				continue
			}
			if memoryRestartRequired(total, available, percent) {
				return &memoryPressure{total: total, available: available, percent: percent}
			}
		}
	}
}

func prepareMemoryRestart(pressure *memoryPressure, timeout time.Duration) {
	// Stay armed through teardown and final CLI logging, even if a writer stalls.
	time.AfterFunc(timeout, func() { os.Exit(1) })
	logMemoryPressure(pressure.total, pressure.available, pressure.percent)
}

func logMemoryPressure(total, available uint64, percent int) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fields := log.Fields{
		"threshold_percent":    percent,
		"host_used_percent":    float64(total-available) * 100 / float64(total),
		"host_total_bytes":     total,
		"host_available_bytes": available,
		"heap_alloc_bytes":     stats.HeapAlloc,
		"heap_inuse_bytes":     stats.HeapInuse,
		"heap_idle_bytes":      stats.HeapIdle,
		"heap_released_bytes":  stats.HeapReleased,
		"runtime_bytes":        stats.Sys - stats.HeapReleased,
		"stack_inuse_bytes":    stats.StackInuse,
		"goroutines":           runtime.NumGoroutine(),
		"gc_cycles":            stats.NumGC,
	}
	if current, err := process.NewProcess(int32(os.Getpid())); err == nil {
		if info, err := current.MemoryInfo(); err == nil {
			fields["process_rss_bytes"] = info.RSS
			fields["process_swap_bytes"] = info.Swap
		}
	}
	log.WithFields(fields).Error("Memory threshold reached; stopping N2X for service manager restart")
}
