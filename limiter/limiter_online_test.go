package limiter

import "testing"

// Metrics and device reports must see the same live registrations.
func TestCountOnlineIPCountsAllUsersWithoutDraining(t *testing.T) {
	l := newDeviceLimitLimiter(t, 6, 0)
	defer l.TrackConnection(tagUUID(t), "192.0.2.1")()
	defer l.TrackConnection(tagUUID(t), "192.0.2.2")()
	defer l.TrackConnection(tagUUID(t), "192.0.2.3")()

	if got := l.CountOnlineIP(); got != 3 {
		t.Fatalf("expected 3 online ips, got %d", got)
	}
	// Second call must return the same count — proving it does not drain.
	if got := l.CountOnlineIP(); got != 3 {
		t.Fatalf("CountOnlineIP must not drain; second call got %d", got)
	}
}

func TestCountOnlineIPZeroWhenEmpty(t *testing.T) {
	l := &Limiter{}
	if got := l.CountOnlineIP(); got != 0 {
		t.Fatalf("expected 0 online ips, got %d", got)
	}
}
