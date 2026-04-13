package node

import (
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	log "github.com/sirupsen/logrus"
)

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
