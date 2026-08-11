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
	setCounter("artx-canary", "native_active_associations", 2)
	setCounter("artx-canary", "native_accepted_associations", 8)
	setCounter("artx-canary", "native_rejected_associations", 3)
	setCounter("artx-canary", "native_datagrams_up", 20)
	setCounter("artx-canary", "native_datagrams_down", 19)
	setCounter("artx-canary", "native_bytes_up", 4096)
	setCounter("artx-canary", "native_bytes_down", 3072)
	setCounter("artx-canary", "native_transport_errors", 1)
	setCounter("artx-canary", "native_target_errors", 2)
	setCounter("other-node", "total_connections", 99)

	got := artXRuntimeStats(manager, "artx-canary")
	if got.ActiveConnections != 2 || got.TotalConnections != 9 {
		t.Fatalf("connection stats = %#v", got)
	}
	if got.ArtX == nil || got.ArtX.AuthenticationSuccess != 7 || got.ArtX.AuthenticationFailure != 2 || got.ArtX.ReplayRejected != 1 || got.ArtX.FallbackHits != 2 || got.ArtX.FallbackErrors != 1 {
		t.Fatalf("ArtX stats = %#v", got.ArtX)
	}
	if got.ArtX.NativeActive != 2 || got.ArtX.NativeAccepted != 8 || got.ArtX.NativeRejected != 3 ||
		got.ArtX.NativeDatagramsUp != 20 || got.ArtX.NativeDatagramsDown != 19 ||
		got.ArtX.NativeBytesUp != 4096 || got.ArtX.NativeBytesDown != 3072 ||
		got.ArtX.NativeTransportErrors != 1 || got.ArtX.NativeTargetErrors != 2 {
		t.Fatalf("native UDP stats = %#v", got.ArtX)
	}
}

func TestRuntimeStatsIncludesNativeUDPState(t *testing.T) {
	core := &Xray{nativeUDPState: map[string]*nativeUDPState{
		"artx-canary": {
			RequestedMode:  "native",
			ActiveMode:     "native",
			ListenerReady:  true,
			CleanupFailure: 1,
			CleanupMillis:  42,
			LastErrorCode:  "native_cleanup_failed",
			LastErrorUnix:  1785667200,
		},
	}}

	got := core.RuntimeStats("artx-canary")
	if got.ArtX == nil || got.ArtX.RequestedUDPMode != "native" || got.ArtX.ActiveUDPMode != "native" ||
		!got.ArtX.NativeListenerReady || got.ArtX.NativeCleanupFailures != 1 ||
		got.ArtX.NativeCleanupMillis != 42 || got.ArtX.LastErrorCode != "native_cleanup_failed" ||
		got.ArtX.LastErrorUnix != 1785667200 {
		t.Fatalf("native UDP state = %#v", got.ArtX)
	}
}
