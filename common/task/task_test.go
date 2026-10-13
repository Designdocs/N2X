package task

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestTaskSchedule(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed", true: "immediate"}[first], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				ts := Task{Interval: time.Second, Execute: func() error {
					calls.Add(1)
					return nil
				}}
				_ = ts.Start(first)
				defer ts.Close()
				_ = ts.Start(first)
				synctest.Wait()
				var want int32
				if first {
					want = 1
				}
				if got := calls.Load(); got != want {
					t.Fatalf("initial executions = %d, want %d", got, want)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				want++
				if got := calls.Load(); got != want {
					t.Fatalf("executions after one interval = %d, want %d", got, want)
				}
				ts.Close()
				ts.Close()
				time.Sleep(time.Second)
				synctest.Wait()
				if got := calls.Load(); got != want {
					t.Fatalf("executions after close = %d, want %d", got, want)
				}
			})
		})
	}
}

func TestTaskWaitsForIntervalAfterExecution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		ts := Task{Interval: time.Second, Execute: func() error {
			if calls.Add(1) == 1 {
				time.Sleep(500 * time.Millisecond)
			}
			return nil
		}}
		_ = ts.Start(true)
		defer ts.Close()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("executions before callback completion plus interval = %d, want 1", got)
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if got := calls.Load(); got != 2 {
			t.Fatalf("executions after callback completion plus interval = %d, want 2", got)
		}
		ts.Close()
	})
}

func TestTaskRestartFromCallbackStopsPreviousRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		ts := Task{Interval: time.Second}
		ts.Execute = func() error {
			if calls.Add(1) == 1 {
				ts.Close()
				ts.Interval = 2 * time.Second
				_ = ts.Start(false)
			}
			return nil
		}
		_ = ts.Start(true)
		defer ts.Close()
		synctest.Wait()
		for want := int32(2); want <= 3; want++ {
			time.Sleep(2 * time.Second)
			synctest.Wait()
			if got := calls.Load(); got != want {
				ts.Close()
				t.Fatalf("executions after restart = %d, want %d", got, want)
			}
		}
		ts.Close()
	})
}

func TestTaskStaleErrorDoesNotStopRestart(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(map[bool]string{false: "periodic", true: "immediate"}[first], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				started := make(chan struct{})
				release := make(chan struct{})
				ts := Task{Interval: time.Second, Execute: func() error {
					if calls.Add(1) == 1 {
						close(started)
						<-release
						return errors.New("old execution failed")
					}
					return nil
				}}
				_ = ts.Start(first)
				defer ts.Close()
				<-started
				ts.Close()
				_ = ts.Start(false)
				close(release)
				synctest.Wait()
				time.Sleep(time.Second)
				synctest.Wait()
				ts.Close()
				if got := calls.Load(); got != 2 {
					t.Fatalf("executions after stale error = %d, want 2", got)
				}
			})
		})
	}
}

func TestTaskStopsOnErrorAndCanRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		ts := Task{Interval: time.Second, Execute: func() error {
			calls.Add(1)
			return errors.New("execution failed")
		}}
		_ = ts.Start(true)
		defer ts.Close()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("executions after error = %d, want 1", got)
		}
		_ = ts.Start(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if got := calls.Load(); got != 2 {
			t.Fatalf("executions after restarting failed task = %d, want 2", got)
		}
	})
}

func TestTaskCloseDuringExecution(t *testing.T) {
	for _, executeError := range []error{nil, errors.New("execution failed")} {
		name := "success"
		if executeError != nil {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				started := make(chan struct{})
				release := make(chan struct{})
				ts := Task{Interval: 0, Execute: func() error {
					calls.Add(1)
					close(started)
					<-release
					return executeError
				}}
				_ = ts.Start(true)
				<-started
				ts.Close()
				close(release)
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if got := calls.Load(); got != 1 {
					t.Fatalf("executions after close during callback = %d, want 1", got)
				}
			})
		})
	}
}
