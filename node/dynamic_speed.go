package node

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/task"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) configureDynamicSpeed(info *panel.NodeInfo) error {
	if c.limiter == nil || info == nil {
		return nil
	}
	directory := os.Getenv("N2X_DYNAMIC_LIMIT_STATE_DIR")
	if directory == "" {
		directory = "/var/lib/N2X/dynamic-speed-limit"
	}
	identity := fmt.Sprintf("%s|%s|%d|%s", c.apiClient.APIHost, info.Type, info.Id, c.apiClient.InstanceID)
	file := filepath.Join(directory, fmt.Sprintf("%x.json", sha256.Sum256([]byte(identity))))
	if err := c.limiter.ConfigureDynamic(info.DynamicSpeedLimit, info.DynamicSpeedCommands, file); err != nil {
		log.WithError(err).WithField("tag", c.tag).Error("Apply dynamic speed policy failed")
		return err
	}
	return nil
}

func runtimePolicyOnlyChange(old, updated *panel.NodeInfo) bool {
	if old == nil || updated == nil {
		return false
	}
	a, b := *maskDeviceLimit(old), *maskDeviceLimit(updated)
	a.DynamicSpeedLimit, b.DynamicSpeedLimit = nil, nil
	a.DynamicSpeedCommands, b.DynamicSpeedCommands = nil, nil
	return reflect.DeepEqual(a, b)
}

func (c *Controller) startDynamicSpeedTasks() {
	// Run for all nodes so an already established unlimited stream can later
	// be taken under panel control without rebuilding the inbound.
	c.dynamicPolicyPeriodic = &task.Task{Interval: conf.DynamicSpeedSampleSeconds * time.Second, Execute: func() error {
		c.sampleDynamicSpeed(time.Now())
		return nil
	}}
	_ = c.dynamicPolicyPeriodic.Start(false)
	wake := make(chan struct{}, 1)
	c.syncStop = make(chan struct{})
	c.apiClient.SetSyncWakeHook(func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	go func() {
		for {
			select {
			case <-c.syncStop:
				return
			case <-wake:
				_ = c.nodeInfoMonitor()
			}
		}
	}()
}

// Never acquire the panel synchronization mutex here: an offline panel may
// block its fetch for many seconds, while local speed policy must keep running.
func (c *Controller) sampleDynamicSpeed(now time.Time) {
	if active := c.limiterRef.Load(); !c.closed.Load() && active != nil {
		active.SampleDynamic(now)
	}
}
