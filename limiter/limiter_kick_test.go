package limiter

import (
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
)

func newDeviceLimitLimiter(t *testing.T, deviceLimit int, aliveIP int) *Limiter {
	t.Helper()
	if limiter == nil {
		Init()
	}
	users := []panel.UserInfo{{Id: 1, Uuid: "uuid-1", DeviceLimit: deviceLimit}}
	l := AddLimiter(t.Name(), &conf.LimitConfig{}, users, map[int]int{1: aliveIP})
	t.Cleanup(func() { DeleteLimiter(t.Name()) })
	return l
}

func tagUUID(t *testing.T) string {
	return format.UserTag(t.Name(), "uuid-1")
}

// A kicked IP must be rejected outright, even when the user is under the
// device limit, and must not linger in the online-IP tracking.
func TestCheckLimitRejectsKickedIP(t *testing.T) {
	l := newDeviceLimitLimiter(t, 3, 1)
	l.MergeKickedList(map[int]map[string]int64{1: {"9.9.9.9": 600}})

	if _, reject := l.CheckLimit(tagUUID(t), "9.9.9.9", true, true); !reject {
		t.Fatal("kicked ip must be rejected")
	}
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("kicked ip must not be tracked online, got %d", got)
	}
	if _, reject := l.CheckLimit(tagUUID(t), "8.8.8.8", true, true); reject {
		t.Fatal("other ips of the same user must still connect")
	}
}

func TestKickExpiresLocally(t *testing.T) {
	l := newDeviceLimitLimiter(t, 3, 1)
	l.MergeKickedList(map[int]map[string]int64{1: {"9.9.9.9": 600}})

	// Simulate expiry by rewinding the stored deadline.
	l.kickedMu.Lock()
	l.KickedIPs[1]["9.9.9.9"] = time.Now().Unix() - 1
	l.kickedMu.Unlock()

	if _, reject := l.CheckLimit(tagUUID(t), "9.9.9.9", true, true); reject {
		t.Fatal("expired kick must not reject")
	}
}

func TestMergeKickedListIgnoresNonPositiveTTLAndPrunes(t *testing.T) {
	l := newDeviceLimitLimiter(t, 3, 1)
	l.MergeKickedList(map[int]map[string]int64{1: {"9.9.9.9": 0}})

	if l.isKicked(1, "9.9.9.9") {
		t.Fatal("ttl<=0 entries must be ignored")
	}
}

// Device-limit enforcement uses limit+tolerance as the effective ceiling so a
// device hopping nodes is not rejected by its own stale alive entry.
func TestCheckLimitAppliesTolerance(t *testing.T) {
	// alive already at the limit: default tolerance 1 must still admit.
	l := newDeviceLimitLimiter(t, 3, 3)
	if _, reject := l.CheckLimit(tagUUID(t), "1.2.3.4", true, true); reject {
		t.Fatal("alive==limit with tolerance 1 must be admitted")
	}
}

func TestCheckLimitRejectsBeyondTolerance(t *testing.T) {
	// alive at limit+tolerance: the next new ip must be rejected.
	l := newDeviceLimitLimiter(t, 3, 4)
	if _, reject := l.CheckLimit(tagUUID(t), "1.2.3.4", true, true); !reject {
		t.Fatal("alive==limit+tolerance must reject a new ip")
	}
}

func TestCheckLimitToleranceZeroRestoresExactEnforcement(t *testing.T) {
	l := newDeviceLimitLimiter(t, 3, 3)
	l.SetDeviceTolerance(0)
	if _, reject := l.CheckLimit(tagUUID(t), "1.2.3.4", true, true); !reject {
		t.Fatal("tolerance 0 must reject at the exact limit")
	}
}

func TestSetDeviceToleranceClampsNegative(t *testing.T) {
	l := newDeviceLimitLimiter(t, 3, 3)
	l.SetDeviceTolerance(-5)
	if got := l.deviceTolerance.Load(); got != 0 {
		t.Fatalf("negative tolerance must clamp to 0, got %d", got)
	}
}

// Known IPs (already online this cycle) must stay unaffected by tolerance
// bookkeeping — regression guard for the OldUserOnline fast path.
func TestCheckLimitKnownIPStillAdmitted(t *testing.T) {
	l := newDeviceLimitLimiter(t, 1, 1)
	l.OldUserOnline = new(sync.Map)
	l.OldUserOnline.Store("1.2.3.4", 1)
	if _, reject := l.CheckLimit(tagUUID(t), "1.2.3.4", true, true); reject {
		t.Fatal("an ip carried over from the previous cycle must stay admitted")
	}
}

func TestCloudflareIsReportedWithoutDeviceAccounting(t *testing.T) {
	for _, ip := range []string{"172.70.247.212", "162.158.111.155", "2606:4700::1234", "::ffff:172.70.247.212", "::ffff:ac46:f7d4"} {
		t.Run(ip, func(t *testing.T) {
			l := newDeviceLimitLimiter(t, 1, 9)
			l.SpeedLimit = 1
			bucket, reject := l.CheckLimit(tagUUID(t), ip, true, true)
			if reject || bucket == nil {
				t.Fatal("CDN must bypass only device accounting and retain speed limiting")
			}
			if _, reject := l.CheckLimit(tagUUID(t), "104.16.0.10", true, true); reject {
				t.Fatal("second CDN IP rejected on existing online map")
			}
			if got := l.CountOnlineIP(); got != 0 {
				t.Fatalf("CDN counted as %d devices", got)
			}
			online, err := l.GetOnlineDevice()
			if err != nil || len(*online) != 2 {
				t.Fatalf("CDN display report missing: %v, %v", online, err)
			}
			if _, reject := l.CheckLimit("unknown-user", ip, true, true); !reject {
				t.Fatal("unknown user admitted")
			}
			for _, entry := range *online {
				l.MergeKickedList(map[int]map[string]int64{1: {entry.IP: 600}})
			}
			if _, reject := l.CheckLimit(tagUUID(t), ip, true, true); !reject {
				t.Fatal("CDN kick bypassed")
			}
			if _, reject := l.CheckLimit(tagUUID(t), "203.0.113.4", true, true); !reject {
				t.Fatal("direct device limit bypassed")
			}
		})
	}
}
