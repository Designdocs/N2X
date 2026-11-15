package node

import (
	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	"testing"
	"time"
)

func TestDynamicSpeedAndDevicePoliciesApplyTogetherWithoutReload(t *testing.T) {
	old := &panel.NodeInfo{Id: 1, Type: "vless", DeviceLimitTolerance: 1}
	updated := *old
	updated.DynamicSpeedLimit = &conf.NodeDynamicSpeedPolicy{Version: 1, Revision: 1}
	updated.DeviceLimitTolerance = 2
	if !runtimePolicyOnlyChange(old, &updated) {
		t.Fatal("common runtime edits require a listener rebuild")
	}
	updated.Type = "trojan"
	if runtimePolicyOnlyChange(old, &updated) {
		t.Fatal("protocol change treated as runtime policy")
	}
}

func TestDynamicSpeedSamplingContinuesWhilePanelSyncIsBlocked(t *testing.T) {
	limiter.Init()
	l := limiter.AddLimiter(t.Name(), &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "user"}}, nil)
	defer limiter.DeleteLimiter(t.Name())
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 2, SustainSeconds: 30, LimitMbps: 1, PenaltySeconds: 60}
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	b, reject := l.CheckLimit(format.UserTag(t.Name(), "user"), "192.0.2.1", true, true)
	if reject {
		t.Fatal("user rejected")
	}
	c := &Controller{limiter: l}
	c.limiterRef.Store(l)
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()
	done := make(chan struct{})
	go func() {
		now := time.Now()
		for range 6 {
			b.Account(3 * 1000000 / 8 * 5)
			now = now.Add(5 * time.Second)
			c.sampleDynamicSpeed(now)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("local sampling waited for the panel network mutex")
	}
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("offline panel prevented local policy enforcement")
	}
}
