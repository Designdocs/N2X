package limiter

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/common/rate"
	"github.com/Designdocs/N2X/conf"
)

func dynamicFixture(t *testing.T, file string) (*Limiter, *conf.NodeDynamicSpeedPolicy, *rate.Controller, string, time.Time) {
	t.Helper()
	Init()
	l := AddLimiter(t.Name(), &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: "ordinary", DeviceLimit: 2}}, nil)
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 50, SustainSeconds: 180, LimitMbps: 5, PenaltySeconds: 1800}
	if err := l.ConfigureDynamic(p, nil, file); err != nil {
		t.Fatal(err)
	}
	key := format.UserTag(t.Name(), "ordinary")
	b, rejected := l.CheckLimit(key, "192.0.2.7", true, true)
	if rejected {
		t.Fatal("fixture user rejected")
	}
	now := time.Now()
	l.userMu.Lock()
	l.resetSampleLocked(key, now)
	l.userMu.Unlock()
	return l, p, b, key, now
}

func feedSpeed(l *Limiter, b *rate.Controller, now time.Time, seconds, mbps int) time.Time {
	for seconds > 0 {
		step := min(seconds, 5)
		seconds -= step
		b.Account(int64(mbps) * 1000000 / 8 * int64(step))
		now = now.Add(time.Duration(step) * time.Second)
		l.SampleDynamic(now)
	}
	return now
}

func TestDynamicSpeedContinuousThresholdAndExistingConnection(t *testing.T) {
	l, p, b, key, now := dynamicFixture(t, "")
	p.OverThresholdPercent = 100
	_ = l.ConfigureDynamic(p, nil, "")
	now = feedSpeed(l, b, now, 180, 50)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("equal threshold must not trigger")
	}
	now = feedSpeed(l, b, now, 175, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("triggered before full duration")
	}
	now = feedSpeed(l, b, now, 5, 60)
	status := l.DynamicSpeedStatus()
	if status.LimitedUsers != 1 || b.Rate() != 625000 {
		t.Fatalf("status=%+v rate=%d", status, b.Rate())
	}
	again, reject := l.CheckLimit(key, "192.0.2.8", true, true)
	if reject || again != b {
		t.Fatal("IP/reconnect replaced the shared controller")
	}
	expiry := status.Penalties[0].ExpiresAt
	penaltyUntil := now.Add(1800 * time.Second)
	now = feedSpeed(l, b, now, 180, 60)
	if l.DynamicSpeedStatus().Penalties[0].ExpiresAt != expiry {
		t.Fatal("penalty extended while in force")
	}
	l.SampleDynamic(penaltyUntil)
	if b.Rate() != 0 || l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("old stream did not recover")
	}
	if _, reject := l.CheckLimit(key, "192.0.2.8", true, true); reject {
		t.Fatal("expiration removed user access")
	}
	_ = now
}

func TestDynamicSpeedStrictRatioAndMissingSampleResetObservation(t *testing.T) {
	l, p, b, _, now := dynamicFixture(t, "")
	p.OverThresholdPercent = 100
	_ = l.ConfigureDynamic(p, nil, "")
	now = feedSpeed(l, b, now, 175, 60)
	now = feedSpeed(l, b, now, 5, 0)
	now = feedSpeed(l, b, now, 175, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("low sample did not reset duration")
	}
	now = now.Add(20 * time.Second)
	l.SampleDynamic(now)
	feedSpeed(l, b, now, 175, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("sampling gap counted as sustained use")
	}
}

func TestDynamicSpeedExemptRoleChangeRetainsBaseAndDeviceLimit(t *testing.T) {
	l, _, b, key, now := dynamicFixture(t, "")
	feedSpeed(l, b, now, 180, 60)
	old := panel.UserInfo{Id: 7, Uuid: "ordinary", DeviceLimit: 2}
	updated := old
	updated.DynamicSpeedExempt = true
	updated.SpeedLimit = 3
	l.UpdateUser(t.Name(), []panel.UserInfo{updated}, []panel.UserInfo{old})
	if b.Rate() != 375000 || l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("role exemption failed or removed base cap")
	}
	if got, reject := l.CheckLimit(key, "192.0.2.7", true, true); reject || got != b {
		t.Fatal("role update replaced identity/controller")
	}
	l.userMu.Lock()
	l.resetSampleLocked(key, now)
	l.userMu.Unlock()
	feedSpeed(l, b, now, 360, 80)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("exempt user penalized")
	}
	info, _ := l.UserLimitInfo.Load(key)
	if info.(*UserLimitInfo).UID != 7 || info.(*UserLimitInfo).DeviceLimit != 2 {
		t.Fatal("exemption damaged access fields")
	}
}

func TestDynamicSpeedPolicyEditsAndReleaseAreIdempotent(t *testing.T) {
	l, p, b, _, now := dynamicFixture(t, "")
	feedSpeed(l, b, now, 180, 60)
	penalty := l.DynamicSpeedStatus().Penalties[0]
	p.Revision++
	p.LimitMbps = 4
	p.PenaltySeconds = 28800
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	if b.Rate() != 500000 || l.DynamicSpeedStatus().Penalties[0].ExpiresAt != penalty.ExpiresAt {
		t.Fatal("edit extended expiry or missed live rate")
	}
	command := conf.DynamicSpeedCommand{ID: "release-one", UserID: 7, PenaltyID: "other-instance", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	_ = l.ConfigureDynamic(p, []conf.DynamicSpeedCommand{command}, "")
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("released a different instance's penalty")
	}
	command.PenaltyID = penalty.ID
	_ = l.ConfigureDynamic(p, []conf.DynamicSpeedCommand{command, command}, "")
	status := l.DynamicSpeedStatus()
	if b.Rate() != 0 || status.LimitedUsers != 0 || len(status.ReleasedCommands) != 1 {
		t.Fatalf("release result %+v", status)
	}
}

func TestDynamicSpeedDisableAndRosterEditKeepExistingController(t *testing.T) {
	l, p, b, _, now := dynamicFixture(t, "")
	feedSpeed(l, b, now, 180, 60)
	old := panel.UserInfo{Id: 7, Uuid: "ordinary", DeviceLimit: 2}
	updated := old
	updated.SpeedLimit = 2
	l.UpdateUser(t.Name(), []panel.UserInfo{updated}, []panel.UserInfo{old})
	if b.Rate() != 250000 || l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("base edit lost penalty or left old stream unchanged")
	}
	p.Enabled = false
	p.Revision++
	_ = l.ConfigureDynamic(p, nil, "")
	if b.Rate() != 250000 || l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("disable damaged base cap")
	}
}

func TestDynamicSpeedPersistenceAndInstanceIsolation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	l, p, b, _, now := dynamicFixture(t, file)
	feedSpeed(l, b, now, 180, 60)
	expires := l.DynamicSpeedStatus().Penalties[0].ExpiresAt
	other := AddLimiter("other-instance", &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: "ordinary"}}, nil)
	_ = other.ConfigureDynamic(p, nil, filepath.Join(t.TempDir(), "state.json"))
	if other.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("penalty crossed instance boundary")
	}
	restarted := AddLimiter("restart", &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: "rotated-credential"}}, nil)
	_ = restarted.ConfigureDynamic(p, nil, file)
	status := restarted.DynamicSpeedStatus()
	if status.LimitedUsers != 1 || status.Penalties[0].ExpiresAt != expires {
		t.Fatalf("restart changed penalty: %+v", status)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("empty state")
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatal("state permissions")
	}
}

func TestDynamicSpeedCredentialRotationKeepsPenaltyAndRemovalPersists(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	l, _, b, _, now := dynamicFixture(t, file)
	feedSpeed(l, b, now, 180, 60)
	penalty := l.DynamicSpeedStatus().Penalties[0]
	old := panel.UserInfo{Id: 7, Uuid: "ordinary", DeviceLimit: 2}
	rotated := old
	rotated.Uuid = "new-credential"
	l.UpdateUser(t.Name(), []panel.UserInfo{rotated}, []panel.UserInfo{old})
	current, rejected := l.CheckLimit(format.UserTag(t.Name(), rotated.Uuid), "192.0.2.8", true, true)
	if rejected || current.Rate() != 625000 || l.DynamicSpeedStatus().Penalties[0].ID != penalty.ID {
		t.Fatal("credential rotation evaded penalty")
	}
	l.UpdateUser(t.Name(), nil, []panel.UserInfo{rotated})
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("deleted user left active penalty")
	}
	restarted := AddLimiter("after-delete", &conf.LimitConfig{}, []panel.UserInfo{rotated}, nil)
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 50, SustainSeconds: 180, LimitMbps: 5, PenaltySeconds: 1800}
	_ = restarted.ConfigureDynamic(p, nil, file)
	if restarted.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("deleted penalty restored from disk")
	}
}

func TestDynamicSpeedConcurrentSamplingRoleChangesAndConnections(t *testing.T) {
	l, p, b, key, now := dynamicFixture(t, "")
	var wg sync.WaitGroup
	errors := make(chan error, 1)
	wg.Go(func() {
		for range 10000 {
			b.Account(65536)
		}
	})
	wg.Go(func() {
		for i := 0; i < 100; i++ {
			copy := *p
			copy.Revision = int64(i + 2)
			copy.Enabled = i%3 != 0
			if err := l.ConfigureDynamic(&copy, nil, ""); err != nil {
				select {
				case errors <- err:
				default:
				}
			}
		}
	})
	wg.Go(func() {
		for range 100 {
			now = now.Add(5 * time.Second)
			l.SampleDynamic(now)
			_ = l.DynamicSpeedStatus()
		}
	})
	wg.Go(func() {
		old := panel.UserInfo{Id: 7, Uuid: "ordinary", DeviceLimit: 2}
		for i := 0; i < 100; i++ {
			updated := old
			updated.DynamicSpeedExempt = i%2 == 0
			l.UpdateUser(t.Name(), []panel.UserInfo{updated}, []panel.UserInfo{old})
			old = updated
		}
	})
	wg.Go(func() {
		for range 100 {
			_, _ = l.CheckLimit(key, "192.0.2.7", true, true)
			_ = l.LimitedUserCount()
		}
	})
	wg.Wait()
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
	if b.Total() != 10000*65536 {
		t.Fatal("concurrent observation lost bytes")
	}
}

func TestDynamicSpeedMissingManagedPolicyKeepsLastGoodAndReportsPolicyError(t *testing.T) {
	l, p, b, _, now := dynamicFixture(t, "")
	feedSpeed(l, b, now, 180, 60)
	_ = l.ConfigureDynamic(nil, nil, "")
	status := l.DynamicSpeedStatus()
	if !status.Enabled || status.LimitedUsers != 1 || status.PolicyError == "" || status.StateError != "" {
		t.Fatalf("last-good policy lost or wrong error: %+v", status)
	}
	_ = l.ConfigureDynamic(p, nil, "")
	if l.DynamicSpeedStatus().PolicyError != "" {
		t.Fatal("valid policy did not clear omission notice")
	}
}

func TestDynamicSpeedBriefDropStillTriggersAfterFullWindow(t *testing.T) {
	l, _, b, _, now := dynamicFixture(t, "")
	now = feedSpeed(l, b, now, 90, 60)
	now = feedSpeed(l, b, now, 5, 30)
	now = feedSpeed(l, b, now, 80, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("triggered before collecting the full observation window")
	}
	feedSpeed(l, b, now, 5, 60)
	status := l.DynamicSpeedStatus()
	if status.Version != 2 || status.OverThresholdPercent != 85 || status.LimitedUsers != 1 || b.Rate() != 625000 {
		t.Fatalf("brief dip evaded the 85%% policy: %+v", status)
	}
	if ratio := status.Penalties[0].OverThresholdPercent; ratio < 97 || ratio >= 100 {
		t.Fatalf("observed ratio = %f", ratio)
	}
}

func TestDynamicSpeedRatioUsesElapsedTimeAtExactBoundary(t *testing.T) {
	for _, highSeconds := range []int{152, 153} {
		t.Run(fmt.Sprintf("%ds_above_threshold", highSeconds), func(t *testing.T) {
			l, _, b, _, now := dynamicFixture(t, "")
			now = feedSpeed(l, b, now, highSeconds, 60)
			feedSpeed(l, b, now, 180-highSeconds, 30)
			want := 0
			if highSeconds == 153 {
				want = 1
			}
			if got := l.DynamicSpeedStatus().LimitedUsers; got != want {
				t.Fatalf("%d/180 high seconds: limited=%d want=%d", highSeconds, got, want)
			}
		})
	}
}

func TestDynamicSpeedRatioWeightsUnequalSampleIntervals(t *testing.T) {
	l, _, b, _, now := dynamicFixture(t, "")
	for range 18 {
		b.Account(60 * 1000000 / 8 * 9)
		now = now.Add(9 * time.Second)
		l.SampleDynamic(now)
		b.Account(30 * 1000000 / 8)
		now = now.Add(time.Second)
		l.SampleDynamic(now)
	}
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("90% elapsed time was mistaken for 50% sample count")
	}
}

func TestDynamicSpeedRollingWindowExpiresOldLowSpeedTime(t *testing.T) {
	l, _, b, _, now := dynamicFixture(t, "")
	now = feedSpeed(l, b, now, 60, 30)
	now = feedSpeed(l, b, now, 150, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("150/180 seconds incorrectly met 85%")
	}
	feedSpeed(l, b, now, 5, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("old low-speed time was not trimmed from the rolling window")
	}
}

func TestDynamicSpeedRatioPolicyChangeRestartsObservation(t *testing.T) {
	l, p, b, _, now := dynamicFixture(t, "")
	feedSpeed(l, b, now, 175, 60)
	p.OverThresholdPercent = 90
	p.Revision++
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	now = time.Now()
	now = feedSpeed(l, b, now, 175, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 0 {
		t.Fatal("ratio edit reused old observation time")
	}
	feedSpeed(l, b, now, 5, 60)
	if l.DynamicSpeedStatus().LimitedUsers != 1 {
		t.Fatal("ratio edit never collected a new full window")
	}
}
