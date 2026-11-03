package cmd

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const restartShutdownTimeout = 10 * time.Second

func waitForShutdown(signals <-chan os.Signal, memory *memoryGuard, scheduled *restartScheduler) error {
	ticker := time.NewTicker(memoryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-signals:
			return nil
		case <-ticker.C:
			percent := int(memory.restartPercent.Load())
			if percent != 0 {
				total, available, err := memory.sample()
				if err != nil {
					log.WithError(err).Warn("Memory guard sample failed")
				} else if memoryRestartRequired(total, available, percent) {
					return &memoryPressure{total: total, available: available, percent: percent}
				}
			}
			if scheduled != nil {
				if reason := scheduled.due(time.Now()); reason != nil {
					return reason
				}
			}
		}
	}
}
