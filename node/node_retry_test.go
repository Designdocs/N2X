package node

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryUntilStartedStopsAfterSuccess(t *testing.T) {
	var calls atomic.Int32
	start := func() error {
		if calls.Add(1) < 3 {
			return errors.New("request cert error")
		}
		return nil
	}

	done := make(chan struct{})
	go func() {
		retryUntilStarted(context.Background(), "node", start, func(int) time.Duration {
			return time.Millisecond
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retry loop did not finish after a successful start")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 start attempts, got %d", got)
	}
}

func TestRetryUntilStartedStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		retryUntilStarted(ctx, "node", func() error {
			calls.Add(1)
			return errors.New("still failing")
		}, func(int) time.Duration {
			return time.Hour
		})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retry loop ignored cancellation")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no start attempt after cancel, got %d", got)
	}
}

func TestNodeStartRetryDelayIsCapped(t *testing.T) {
	expected := []time.Duration{
		30 * time.Second,
		time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		5 * time.Minute,
		5 * time.Minute,
	}
	for i, want := range expected {
		if got := nodeStartRetryDelay(i + 1); got != want {
			t.Fatalf("attempt %d: expected %s, got %s", i+1, want, got)
		}
	}
	if got := nodeStartRetryDelay(64); got != 5*time.Minute {
		t.Fatalf("expected large attempts to stay capped, got %s", got)
	}
}

func TestNodeCloseWithoutStartedControllers(t *testing.T) {
	n := &Node{}
	n.Close()
}
