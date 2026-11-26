package scanguard

import (
	"net/netip"
	"testing"
	"time"
)

func TestConfirmedVisitorBan(t *testing.T) {
	t.Setenv("N2X_WS_SCAN_STATE_DIR", t.TempDir())
	v := verifiedVisitor{t.Name(), netip.MustParseAddr("192.0.2.1")}
	now := time.Now()
	hit := func(path string, want bool) {
		t.Helper()
		got, err := v.observe(path, now)
		if err != nil || got != want {
			t.Fatalf("%s: blocked=%t, err=%v", path, got, err)
		}
	}
	for range 8 {
		hit("/ws", false)
		now = now.Add(time.Second)
	}
	now = now.Add(roundGap)
	for _, p := range []string{"/a", "/b", "/c"} {
		hit(p, false)
	}
	now = now.Add(roundGap - time.Second)
	hit("/d", false)
	now = now.Add(roundGap)
	hit("/.env", false)
	hit("/.git/config", false)
	hit("/wp-admin", true)
	if !v.blocked() {
		t.Fatal("incorrect persistent ban lifetime")
	}
	if (verifiedVisitor{"other", v.ip}).blocked() {
		t.Fatal("ban escaped node")
	}
}
