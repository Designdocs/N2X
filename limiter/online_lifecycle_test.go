package limiter

import (
	"fmt"
	"sync"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
)

func TestOnlineSnapshotKeepsLiveConnectionsAcrossReports(t *testing.T) {
	l := newDeviceLimitLimiter(t, 6, 0)
	first := l.TrackConnection(tagUUID(t), "192.0.2.1")
	second := l.TrackConnection(tagUUID(t), "::ffff:192.0.2.1")
	for range 3 {
		devices, err := l.GetOnlineDevice()
		if err != nil || len(*devices) != 1 || (*devices)[0] != (panel.OnlineUser{UID: 1, IP: "192.0.2.1"}) {
			t.Fatalf("live snapshot = %v, %v", devices, err)
		}
	}
	first()
	first()
	if got := l.CountOnlineIP(); got != 1 {
		t.Fatalf("closing one shared-IP connection left %d devices, want 1", got)
	}
	second()
	devices, _ := l.GetOnlineDevice()
	if len(*devices) != 0 || l.CountOnlineIP() != 0 {
		t.Fatalf("closed connections remain online: %v", devices)
	}
}

func TestClosedIPsDoNotSurvivePolicyUpdates(t *testing.T) {
	l := newDeviceLimitLimiter(t, 0, 0)
	l.TrackConnection(tagUUID(t), "198.51.100.1")()
	oldUser := panel.UserInfo{Id: 1, Uuid: "uuid-1"}
	newUser := oldUser
	newUser.DeviceLimit = 20
	l.UpdateUser(t.Name(), []panel.UserInfo{newUser}, []panel.UserInfo{oldUser})
	for i := 1; i <= 9; i++ {
		l.TrackConnection(tagUUID(t), fmt.Sprintf("192.0.2.%d", i))()
	}
	devices, _ := l.GetOnlineDevice()
	if len(*devices) != 0 {
		t.Fatalf("nine closed connections remain online: %v", devices)
	}
	closeLive := l.TrackConnection(tagUUID(t), "192.0.2.10")
	l.UpdateUser(t.Name(), []panel.UserInfo{oldUser}, []panel.UserInfo{newUser})
	if got := l.CountOnlineIP(); got != 1 {
		t.Fatalf("policy update lost a live connection: %d", got)
	}
	closeLive()
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("policy update prevented cleanup: %d", got)
	}
}

func TestOnlineIPsAreIsolatedByAuthenticatedUser(t *testing.T) {
	l := newDeviceLimitLimiter(t, 6, 0)
	l.UpdateUser(t.Name(), []panel.UserInfo{{Id: 2, Uuid: "uuid-2"}}, nil)
	closeFirst := l.TrackConnection(tagUUID(t), "192.0.2.1")
	closeSecond := l.TrackConnection(format.UserTag(t.Name(), "uuid-2"), "192.0.2.1")
	devices, _ := l.GetOnlineDevice()
	if len(*devices) != 2 {
		t.Fatalf("shared public IP merged separate users: %v", devices)
	}
	closeFirst()
	devices, _ = l.GetOnlineDevice()
	if len(*devices) != 1 || (*devices)[0].UID != 2 {
		t.Fatalf("closing one user affected another: %v", devices)
	}
	closeSecond()
}

func TestOldConnectionCannotRemoveReplacementIdentity(t *testing.T) {
	l := newDeviceLimitLimiter(t, 6, 0)
	closeOld := l.TrackConnection(tagUUID(t), "192.0.2.1")
	l.UpdateUser(t.Name(), nil, []panel.UserInfo{{Id: 1, Uuid: "uuid-1"}})
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("removed user remains online: %d", got)
	}
	l.UpdateUser(t.Name(), []panel.UserInfo{{Id: 2, Uuid: "uuid-1"}}, nil)
	closeNew := l.TrackConnection(tagUUID(t), "192.0.2.1")
	closeOld()
	devices, _ := l.GetOnlineDevice()
	if len(*devices) != 1 || (*devices)[0].UID != 2 {
		t.Fatalf("old close affected replacement identity: %v", devices)
	}
	closeNew()
}

func TestUntrustedOnlineSourcesAreNotReported(t *testing.T) {
	l := newDeviceLimitLimiter(t, 6, 0)
	l.TrackConnection("unknown-user", "192.0.2.1")()
	l.TrackConnection(tagUUID(t), "not-an-ip")()
	devices, _ := l.GetOnlineDevice()
	if len(*devices) != 0 {
		t.Fatalf("untrusted identity or source was reported: %v", devices)
	}
}

func TestConcurrentOnlineSnapshotAndConnectionClose(t *testing.T) {
	l := newDeviceLimitLimiter(t, 0, 0)
	var workers sync.WaitGroup
	for i := range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				ip := fmt.Sprintf("192.0.2.%d", i+1)
				if _, reject := l.CheckLimit(tagUUID(t), ip, true, true); reject {
					t.Error("valid connection rejected during concurrent snapshots")
				}
				close := l.TrackConnection(tagUUID(t), ip)
				l.GetOnlineDevice()
				l.CountOnlineIP()
				close()
			}
		}()
	}
	workers.Wait()
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("concurrent closes left %d devices", got)
	}
}
