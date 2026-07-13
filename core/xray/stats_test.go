package xray

import (
	"context"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
)

func TestArtXRuntimeStatsReadsOnlyRequestedInbound(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	setCounter := func(tag, name string, value int64) {
		counter, registerErr := manager.RegisterCounter("inbound>>>" + tag + ">>>artx>>>" + name)
		if registerErr != nil {
			t.Fatal(registerErr)
		}
		counter.Add(value)
	}
	setCounter("artx-canary", "active_connections", 2)
	setCounter("artx-canary", "total_connections", 9)
	setCounter("artx-canary", "authentication_success", 7)
	setCounter("artx-canary", "authentication_failure", 2)
	setCounter("artx-canary", "replay_rejected", 1)
	setCounter("artx-canary", "fallback_hits", 2)
	setCounter("artx-canary", "fallback_errors", 1)
	setCounter("other-node", "total_connections", 99)

	got := artXRuntimeStats(manager, "artx-canary")
	if got.ActiveConnections != 2 || got.TotalConnections != 9 {
		t.Fatalf("connection stats = %#v", got)
	}
	if got.ArtX == nil || got.ArtX.AuthenticationSuccess != 7 || got.ArtX.AuthenticationFailure != 2 || got.ArtX.ReplayRejected != 1 || got.ArtX.FallbackHits != 2 || got.ArtX.FallbackErrors != 1 {
		t.Fatalf("ArtX stats = %#v", got.ArtX)
	}
}
