package node

import (
	"github.com/Designdocs/N2X/api/panel"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	// A reload may start a new task before the previous request has returned.
	c.userReportMu.Lock()
	defer c.userReportMu.Unlock()
	userTraffic, _ := c.server.GetUserTrafficSlice(c.tag, true)
	if len(userTraffic) > 0 {
		// Feed running totals so the metrics task can derive rate.
		// Updated before the network call so a panel hiccup doesn't desync
		// the local accounting.
		var addedUp, addedDown int64
		for i := range userTraffic {
			addedUp += userTraffic[i].Upload
			addedDown += userTraffic[i].Download
		}
		c.totalUploadBytes.Add(addedUp)
		c.totalDownloadBytes.Add(addedDown)

		err = c.apiClient.ReportUserTraffic(userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
			log.WithField("tag", c.tag).Debugf("User traffic: %+v", userTraffic)
		}
	}

	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else {
		// Keep the configured probe-traffic filter for users not yet reported.
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			_, alreadyReported := c.reportedDeviceUsers[traffic.UID]
			if !alreadyReported && total < int64(c.Options.DeviceOnlineMinTraffic*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		currentUsers := make(map[int]struct{})
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
			currentUsers[onlineuser.UID] = struct{}{}
		}
		// HTTP alive reports need explicit removals; an empty object is a no-op.
		for uid := range c.reportedDeviceUsers {
			if _, remains := currentUsers[uid]; !remains {
				data[uid] = []string{}
			}
		}
		if c.reportedDeviceUsers == nil {
			c.reportedDeviceUsers = make(map[int]struct{})
		}
		// A failed request may still have reached the panel before its reply was lost.
		for uid := range currentUsers {
			c.reportedDeviceUsers[uid] = struct{}{}
		}
		if err = c.apiClient.ReportNodeOnlineUsers(&data); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			c.reportedDeviceUsers = currentUsers
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
			log.WithField("tag", c.tag).Debugf("Online users: %+v", data)
		}
	}

	userTraffic = nil
	return nil
}
