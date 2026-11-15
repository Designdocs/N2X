package node

import (
	"errors"
	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type exemptionRosterCore struct {
	rosterStubCore
	addErr error
}

func (c *exemptionRosterCore) AddUsers(params *vCore.AddUsersParams) (int, error) {
	return len(params.Users), c.addErr
}

func TestExemptionRosterRetriesAfterCoreApplyFailure(t *testing.T) {
	rosterRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			http.NotFound(w, r) // Retain the already-running policy while offline.
		case "/api/v1/server/UniProxy/user":
			rosterRequests++
			w.Header().Set("ETag", "roster-two")
			w.Header().Set("X-Dynamic-Speed-Exemptions-Revision", "2")
			if r.Header.Get("If-None-Match") == "roster-two" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(`{"users":[{"id":7,"uuid":"ordinary","dynamic_speed_exempt":true},{"id":8,"uuid":"added"}]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		}
	}))
	defer server.Close()
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "dummy", NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	core := &exemptionRosterCore{addErr: errors.New("temporary core failure")}
	c := NewController(core, client, &conf.Options{}, nil)
	c.tag = t.Name()
	c.info = &panel.NodeInfo{Type: "vless"}
	c.userList = []panel.UserInfo{{Id: 7, Uuid: "ordinary"}}
	c.limiter = limiter.AddLimiter(c.tag, &conf.LimitConfig{}, c.userList, nil)
	c.limiterRef.Store(c.limiter)
	defer limiter.DeleteLimiter(c.tag)
	p := conf.DefaultNodeDynamicSpeedPolicy()
	p.Enabled, p.ExemptionsRevision = true, 2
	if err := c.limiter.ConfigureDynamic(&p, nil, ""); err != nil {
		t.Fatal(err)
	}
	c.limiter.AcknowledgeDynamicExemptions(1)
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if c.limiter.DynamicSpeedStatus().ExemptionsAppliedRevision != 1 || len(c.userList) != 1 {
		t.Fatal("failed core update acknowledged the new roster")
	}
	core.addErr = nil
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if c.limiter.DynamicSpeedStatus().ExemptionsAppliedRevision != 2 || len(c.userList) != 2 || !c.userList[0].DynamicSpeedExempt || rosterRequests != 2 {
		t.Fatal("failed update was cached instead of retried")
	}
}

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
