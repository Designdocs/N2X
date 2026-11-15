package rate

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestControllerAggregatesConcurrentDirections(t *testing.T) {
	c := NewController(125000)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wg.Go(func() { errors <- c.Wait(ctx, 62500) })
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("connections did not share an aggregate budget")
	}
}

func TestControllerPolicyChangeWakesExistingWait(t *testing.T) {
	c := NewController(1)
	done := make(chan error, 1)
	go func() { done <- c.Wait(context.Background(), 16384) }()
	c.SetRate(0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old waiter not released")
	}
	c.SetRate(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Wait(ctx, 1); err == nil {
		t.Fatal("canceled wait succeeded")
	}
}

func BenchmarkControllerUnlimited(b *testing.B) {
	c := NewController(0)
	ctx := context.Background()
	for b.Loop() {
		_ = c.Wait(ctx, 32768)
		c.Account(32768)
	}
}
