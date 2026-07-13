package limiter

import (
	"sync"
	"testing"
)

// TestCountOnlineIPCountsAllUsersWithoutDraining locks in the key property that
// makes CountOnlineIP safe for metrics sampling: it peeks the live online-IP
// tracking without resetting it, unlike GetOnlineDevice which drains every
// traffic cycle.
func TestCountOnlineIPCountsAllUsersWithoutDraining(t *testing.T) {
	l := &Limiter{UserOnlineIP: new(sync.Map)}

	u1 := new(sync.Map)
	u1.Store("1.1.1.1", 1)
	u1.Store("2.2.2.2", 1)
	l.UserOnlineIP.Store("tag-uuid-1", u1)

	u2 := new(sync.Map)
	u2.Store("3.3.3.3", 2)
	l.UserOnlineIP.Store("tag-uuid-2", u2)

	if got := l.CountOnlineIP(); got != 3 {
		t.Fatalf("expected 3 online ips, got %d", got)
	}
	// Second call must return the same count — proving it does not drain.
	if got := l.CountOnlineIP(); got != 3 {
		t.Fatalf("CountOnlineIP must not drain; second call got %d", got)
	}
}

func TestCountOnlineIPZeroWhenEmpty(t *testing.T) {
	l := &Limiter{UserOnlineIP: new(sync.Map)}
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("expected 0 online ips, got %d", got)
	}
}
