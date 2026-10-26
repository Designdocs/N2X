package dispatcher

import (
	"sync"
	"testing"
)

func TestConcurrentFirstStreamsShareTrafficCounter(t *testing.T) {
	for range 50 {
		dispatcher := new(DefaultDispatcher)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				<-start
				storage := dispatcher.trafficCounterFor("node").GetCounter("user")
				storage.UpCounter.Add(32768)
				storage.DownCounter.Add(32768)
			})
		}
		close(start)
		wg.Wait()
		counter := dispatcher.trafficCounterFor("node")
		if up, down := counter.GetUpCount("user"), counter.GetDownCount("user"); up != 32*32768 || down != 32*32768 {
			t.Fatalf("first streams lost traffic: up=%d down=%d", up, down)
		}
	}
}
