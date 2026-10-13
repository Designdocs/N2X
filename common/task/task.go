package task

import (
	"sync"
	"time"
)

type Task struct {
	Interval time.Duration
	Execute  func() error
	access   sync.Mutex
	running  bool
	stop     chan struct{}
}

func (t *Task) Start(first bool) error {
	t.access.Lock()
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.stop = make(chan struct{})
	stop, interval, execute := t.stop, t.Interval, t.Execute
	t.access.Unlock()

	go func() {
		defer func() {
			t.access.Lock()
			// A callback may have already replaced this run with a new one.
			if t.running && t.stop == stop {
				t.running = false
				close(stop)
			}
			t.access.Unlock()
		}()

		delay := interval
		if first {
			delay = 0
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
			case <-stop:
				return
			}
			select {
			case <-stop:
				return
			default:
			}

			if err := execute(); err != nil {
				return
			}
			timer.Reset(interval)
		}
	}()

	return nil
}

func (t *Task) Close() {
	t.access.Lock()
	if t.running {
		t.running = false
		close(t.stop)
	}
	t.access.Unlock()
}
