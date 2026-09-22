package node

import (
	"reflect"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/Designdocs/N2X/api/panel"
)

// deviceLimitOnlyChange reports whether the only thing that moved between
// two node bodies is the panel's device-limit policy: the tolerance or the
// operator ignore list. The ignore list carries resolved relay exits with
// dynamic addresses, so it changes routinely; the limiter takes both in
// place, and a full reload would cost the node every session for nothing.
func deviceLimitOnlyChange(old, updated *panel.NodeInfo) bool {
	if old == nil || updated == nil {
		return false
	}
	if old.DeviceLimitTolerance == updated.DeviceLimitTolerance &&
		slices.Equal(old.DeviceLimitIgnoredIPs, updated.DeviceLimitIgnoredIPs) {
		return false
	}
	return reflect.DeepEqual(maskDeviceLimit(old), maskDeviceLimit(updated))
}

// maskDeviceLimit copies a node body with the device-limit policy blanked so
// the two bodies can be compared on everything else. Shallow apart from the
// two fields being rewritten; the original is left untouched.
func maskDeviceLimit(info *panel.NodeInfo) *panel.NodeInfo {
	masked := *info
	masked.DeviceLimitTolerance = 0
	masked.DeviceLimitIgnoredIPs = nil
	return &masked
}

// applyDeviceLimitInPlace hands the new policy to the running limiter.
func (c *Controller) applyDeviceLimitInPlace(info *panel.NodeInfo) {
	c.limiter.SetDeviceTolerance(info.DeviceLimitTolerance)
	c.limiter.SetIgnoredPrefixes(info.DeviceLimitIgnoredIPs)
	log.WithFields(log.Fields{
		"tag":         c.tag,
		"tolerance":   info.DeviceLimitTolerance,
		"ignored_ips": len(info.DeviceLimitIgnoredIPs),
	}).Info("Device-limit policy updated in place, node kept online")
}
