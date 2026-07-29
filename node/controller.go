package node

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/task"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 *panel.Client
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[string]int64
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	aliveMu                   sync.RWMutex
	info                      *panel.NodeInfo
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	nodeStatusReportPeriodic  *task.Task
	nodeMetricsReportPeriodic *task.Task
	httpsRedirectManager      *httpsRedirectManager

	// cumulative byte counters maintained by reportUserTrafficTask and
	// drained by reportNodeMetricsTask to derive inbound/outbound rates
	totalUploadBytes    atomic.Int64
	totalDownloadBytes  atomic.Int64
	lastMetricsUpload   int64
	lastMetricsDownload int64
	lastMetricsAt       time.Time

	*conf.Options
}

// NewController return a Node controller with default parameters.
func NewController(
	server vCore.Core,
	api *panel.Client,
	config *conf.Options,
	redirectManager *httpsRedirectManager,
) *Controller {
	controller := &Controller{
		server:               server,
		Options:              config,
		apiClient:            api,
		httpsRedirectManager: redirectManager,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	// First fetch Node Info
	var err error
	node, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	// Update user
	c.userList, err = c.apiClient.GetUserList()
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	if len(c.userList) == 0 {
		return errors.New("add users error: not have any user")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	c.aliveMap = cloneAliveMap(c.aliveMap)
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name
	}

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	c.limiter = l
	c.apiClient.SetAliveUpdateHook(c.setAliveMap)
	if node.Security == panel.Tls {
		err = c.requestCert(node)
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	c.prepareHTTPSRedirect(node)
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.refreshHTTPSRedirect(node)
	c.startTasks(node)
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	c.apiClient.SetAliveUpdateHook(nil)
	limiter.DeleteLimiter(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.dynamicSpeedLimitPeriodic != nil {
		c.dynamicSpeedLimitPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	if c.nodeStatusReportPeriodic != nil {
		c.nodeStatusReportPeriodic.Close()
	}
	if c.nodeMetricsReportPeriodic != nil {
		c.nodeMetricsReportPeriodic.Close()
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}

func (c *Controller) setAliveMap(alive map[int]int) {
	snapshot := cloneAliveMap(alive)
	c.aliveMu.Lock()
	c.aliveMap = snapshot
	c.aliveMu.Unlock()

	if c.limiter != nil {
		c.limiter.UpdateAliveList(snapshot)
	}
}

func (c *Controller) activeUserCount() int {
	c.aliveMu.RLock()
	defer c.aliveMu.RUnlock()
	return len(c.aliveMap)
}

// activeConnectionCount samples the live online-IP count from the limiter for
// the node metrics popup. Returns 0 before the limiter is wired so an early
// metrics tick cannot panic.
func (c *Controller) activeConnectionCount() int {
	if c.limiter == nil {
		return 0
	}
	return c.limiter.CountOnlineIP()
}

func cloneAliveMap(alive map[int]int) map[int]int {
	cloned := make(map[int]int, len(alive))
	for uid, count := range alive {
		if uid > 0 && count > 0 {
			cloned[uid] = count
		}
	}
	return cloned
}
