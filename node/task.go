package node

import (
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/task"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Interval: node.PullInterval,
		Execute:  c.nodeInfoMonitor,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
	}
	log.WithField("tag", c.tag).Info("Start monitor node status")
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	// periodic node load report for X-Board /UniProxy/status endpoint
	statusInterval := node.PushInterval
	if statusInterval < time.Minute {
		statusInterval = time.Minute
	}
	c.nodeStatusReportPeriodic = &task.Task{
		Interval: statusInterval,
		Execute:  c.reportNodeStatusTask,
	}
	log.WithField("tag", c.tag).Info("Start report node load status")
	_ = c.nodeStatusReportPeriodic.Start(true)
	// periodic rich metrics report — feeds the admin "节点状态" popup with
	// uptime/goroutines/users/speeds. Reuses the load interval so both
	// reports stay in sync and respect the operator-tunable cadence.
	c.nodeMetricsReportPeriodic = &task.Task{
		Interval: statusInterval,
		Execute:  c.reportNodeMetricsTask,
	}
	log.WithField("tag", c.tag).Info("Start report node metrics")
	_ = c.nodeMetricsReportPeriodic.Start(true)
	if node.Security == panel.Tls {
		switch c.CertConfig.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && c.LimitConfig.DynamicSpeedLimitConfig != nil {
		interval := time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.Periodic) * time.Second
		if interval <= 0 {
			interval = time.Minute
		}
		c.traffic = make(map[string]int64)
		c.dynamicSpeedLimitPeriodic = &task.Task{
			Interval: interval,
			Execute:  c.SpeedChecker,
		}
		log.Printf("[%s: %d] Start dynamic speed limit", c.apiClient.NodeType, c.apiClient.NodeId)
		_ = c.dynamicSpeedLimitPeriodic.Start(false)
	}
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// get node info
	newN, err := c.apiClient.GetNodeInfo()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	// get user info
	newU, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get alive list failed")
		return nil
	}
	if newN != nil {
		c.info = newN
		// nodeInfo changed
		if newU != nil {
			c.userList = newU
		}
		c.traffic = make(map[string]int64)
		// Remove old node
		log.WithField("tag", c.tag).Info("Node changed, reload")
		err = c.server.DelNode(c.tag)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Panic("Delete node failed")
			return nil
		}

		// Update limiter
		oldTag := c.tag
		if len(c.Options.Name) == 0 {
			c.tag = c.buildNodeTag(newN)
		}
		limiter.DeleteLimiter(oldTag)
		c.limiter = limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, newA)
		// update alive list
		if newA != nil {
			c.setAliveMap(newA)
		}
		// Update rule
		err = c.limiter.UpdateRule(&newN.Rules)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Update Rule failed")
			return nil
		}

		// check cert
		if newN.Security == panel.Tls {
			err = c.requestCert()
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Error("Request cert failed")
				return nil
			}
		}
		// add new node
		err = c.server.AddNode(c.tag, newN, c.Options)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Panic("Add node failed")
			return nil
		}
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			Users:    c.userList,
			NodeInfo: newN,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return nil
		}
		// Check interval
		if c.nodeInfoMonitorPeriodic.Interval != newN.PullInterval &&
			newN.PullInterval != 0 {
			c.nodeInfoMonitorPeriodic.Interval = newN.PullInterval
			c.nodeInfoMonitorPeriodic.Close()
			_ = c.nodeInfoMonitorPeriodic.Start(false)
		}
		if c.userReportPeriodic.Interval != newN.PushInterval &&
			newN.PushInterval != 0 {
			c.userReportPeriodic.Interval = newN.PushInterval
			c.userReportPeriodic.Close()
			_ = c.userReportPeriodic.Start(false)
		}
		log.WithField("tag", c.tag).Infof("Added %d new users", len(c.userList))
		// exit
		return nil
	}
	// update alive list
	if newA != nil {
		c.setAliveMap(newA)
	}
	// node no changed, check users
	if len(newU) == 0 {
		return nil
	}
	changes := compareUserList(c.userList, newU)
	if len(changes.deleted) > 0 {
		// have deleted users
		err = c.server.DelUsers(changes.deleted, c.tag, c.info)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete users failed")
			return nil
		}
	}
	if len(changes.added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    changes.added,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return nil
		}
	}
	if len(changes.limiterAdded) > 0 || len(changes.limiterDeleted) > 0 {
		// update Limiter
		c.limiter.UpdateUser(c.tag, changes.limiterAdded, changes.limiterDeleted)
		// clear traffic record
		if c.LimitConfig.EnableDynamicSpeedLimit {
			for i := range changes.deleted {
				delete(c.traffic, changes.deleted[i].Uuid)
			}
		}
	}
	c.userList = newU
	if len(changes.added)+len(changes.deleted)+len(changes.limiterAdded)+len(changes.limiterDeleted) != 0 {
		log.WithField("tag", c.tag).
			Infof("%d user deleted, %d user added, %d limiter updated",
				len(changes.deleted),
				len(changes.added),
				len(changes.limiterAdded))
	}
	return nil
}

func (c *Controller) SpeedChecker() error {
	if c.LimitConfig.DynamicSpeedLimitConfig == nil {
		return nil
	}
	for u, t := range c.traffic {
		if t >= c.LimitConfig.DynamicSpeedLimitConfig.Traffic {
			err := c.limiter.UpdateDynamicSpeedLimit(c.tag, u,
				c.LimitConfig.DynamicSpeedLimitConfig.SpeedLimit,
				time.Now().Add(time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.ExpireTime)*time.Minute))
			if err != nil {
				log.WithField("err", err).Error("Update dynamic speed limit failed")
			}
			delete(c.traffic, u)
		}
	}
	return nil
}
