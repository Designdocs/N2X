package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

func TestNextRestartTimeRespectsMinimumUptimeWindowAndTimezone(t *testing.T) {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		earliest string
		day      int
	}{
		{"2026-11-05T02:00:00+08:00", 5},
		{"2026-11-05T03:40:12+08:00", 5},
		{"2026-11-05T04:59:01+08:00", 6},
		{"2026-11-05T05:00:00+08:00", 6},
		{"2026-11-05T18:00:00+08:00", 6},
	} {
		earliest, err := time.Parse(time.RFC3339, tt.earliest)
		if err != nil {
			t.Fatal(err)
		}
		for range 100 {
			next := nextRestartTime(earliest, 3*time.Hour, 5*time.Hour, location)
			if next.Before(earliest) || !inRestartWindow(next, 3*time.Hour, 5*time.Hour, location) || next.In(location).Day() != tt.day || next.Second() != 0 {
				t.Fatalf("earliest=%s, next=%s, want day %d within window", earliest, next, tt.day)
			}
		}
	}
}

func TestRestartWindowHandlesDaylightSaving(t *testing.T) {
	location, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, earliest string
		start, end     time.Duration
		day            int
	}{
		{"spring default", "2026-03-08T00:00:00-08:00", 3 * time.Hour, 5 * time.Hour, 8},
		{"fall default", "2026-11-01T00:00:00-07:00", 3 * time.Hour, 5 * time.Hour, 1},
		{"skipped hour", "2026-03-08T00:00:00-08:00", 2 * time.Hour, 3 * time.Hour, 9},
		{"partly skipped end", "2026-03-08T00:00:00-08:00", time.Hour, 150 * time.Minute, 8},
		{"repeated hour", "2026-11-01T00:00:00-07:00", time.Hour, 2 * time.Hour, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			earliest, err := time.Parse(time.RFC3339, tt.earliest)
			if err != nil {
				t.Fatal(err)
			}
			for range 100 {
				next := nextRestartTime(earliest, tt.start, tt.end, location)
				if next.Before(earliest) || !inRestartWindow(next, tt.start, tt.end, location) || next.In(location).Day() != tt.day {
					t.Fatalf("next=%s, want day %d in window", next, tt.day)
				}
			}
		})
	}
}

func TestSchedulerPreservesReloadAndResetsOnlyWhenChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &restartScheduler{}
		options := conf.New().ScheduledRestart
		s.configure(options)
		if !s.next.IsZero() {
			t.Fatal("default schedule must remain disabled")
		}
		options.Enabled, options.Timezone = true, "UTC"
		enabledAt := time.Now()
		s.configure(options)
		first, eligible := s.next, s.eligible
		if !eligible.Equal(enabledAt.Add(72*time.Hour)) || first.Before(eligible) {
			t.Fatalf("eligible=%s, next=%s, enabled=%s", eligible, first, enabledAt)
		}
		time.Sleep(24 * time.Hour)
		s.configure(options)
		if !s.next.Equal(first) || !s.eligible.Equal(eligible) {
			t.Fatal("unchanged reload postponed the restart")
		}
		options.IntervalDays = 7
		s.configure(options)
		if !s.eligible.Equal(time.Now().Add(7 * 24 * time.Hour)) {
			t.Fatal("changed interval was not applied")
		}
		options.Enabled = false
		s.configure(options)
		if !s.next.IsZero() || s.due(first.Add(30*24*time.Hour)) != nil {
			t.Fatal("disabled plan still triggers")
		}
		options.Enabled = true
		time.Sleep(time.Hour)
		s.configure(options)
		if !s.eligible.Equal(time.Now().Add(7 * 24 * time.Hour)) {
			t.Fatal("re-enabled plan did not start a fresh interval")
		}
	})
}

func TestSchedulerDueOnceAndNeverOutsideWindow(t *testing.T) {
	options := conf.New().ScheduledRestart
	options.Enabled, options.Timezone = true, "UTC"
	s := &restartScheduler{}
	s.configure(options)
	first := s.next
	if s.due(first.Add(-time.Nanosecond)) != nil {
		t.Fatal("restart fired early")
	}
	reason := s.due(first)
	if reason == nil || !reason.at.Equal(first) {
		t.Fatal("restart did not fire at the planned time")
	}
	if s.due(first) != nil {
		t.Fatal("restart fired twice")
	}

	// Configure a fresh scheduler, then simulate waking up after its window.
	s = &restartScheduler{}
	s.configure(options)
	first = s.next
	missed := time.Date(first.Year(), first.Month(), first.Day(), 6, 0, 0, 0, time.UTC)
	if s.due(missed) != nil {
		t.Fatal("missed window caused a daytime restart")
	}
	if !s.next.After(missed) || s.next.Day() == missed.Day() {
		t.Fatal("missed window did not move to the next day")
	}
	if s.due(s.next) == nil {
		t.Fatal("rescheduled restart did not fire")
	}
}

func TestScheduledRestartWorksWithDisabledOrFailingMemoryGuard(t *testing.T) {
	for _, threshold := range []int64{0, 90} {
		synctest.Test(t, func(t *testing.T) {
			memory := &memoryGuard{sample: func() (uint64, uint64, error) { return 0, 0, errors.New("probe failed") }}
			memory.restartPercent.Store(threshold)
			s := &restartScheduler{eligible: time.Now(), next: time.Now().Add(memoryCheckInterval), start: 0, end: 24 * time.Hour, location: time.UTC}
			result := make(chan error, 1)
			go func() { result <- waitForShutdown(make(chan os.Signal), memory, s) }()
			time.Sleep(memoryCheckInterval)
			var reason *scheduledRestart
			if err := <-result; !errors.As(err, &reason) {
				t.Fatalf("expected scheduled exit, got %v", err)
			}
		})
	}
}

func TestSchedulerConcurrentReloadAndChecks(t *testing.T) {
	s := &restartScheduler{}
	options := conf.New().ScheduledRestart
	options.Enabled, options.Timezone = true, "UTC"
	s.configure(options)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				s.configure(options)
				if s.due(time.Now()) != nil {
					t.Error("restart fired before minimum uptime")
				}
			}
		})
	}
	workers.Wait()
}

func TestMemoryPressureStillTakesPriorityOverScheduledRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		memory := &memoryGuard{sample: func() (uint64, uint64, error) { return 1000, 100, nil }}
		memory.restartPercent.Store(90)
		s := &restartScheduler{eligible: time.Now(), next: time.Now(), start: 0, end: 24 * time.Hour, location: time.UTC}
		result := make(chan error, 1)
		go func() { result <- waitForShutdown(make(chan os.Signal), memory, s) }()
		time.Sleep(memoryCheckInterval)
		var pressure *memoryPressure
		if err := <-result; !errors.As(err, &pressure) {
			t.Fatalf("expected immediate memory pressure exit, got %v", err)
		}
	})
}

func TestScheduledRestartDeadlineSurvivesBlockedLogging(t *testing.T) {
	const probeEnv = "N2X_TEST_SCHEDULED_RESTART_PROBE"
	if os.Getenv(probeEnv) == "1" {
		log.SetOutput(blockedMemoryLog{})
		prepareScheduledRestart(&scheduledRestart{at: time.Now()}, 50*time.Millisecond)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScheduledRestartDeadlineSurvivesBlockedLogging$")
	probe.Env = append(os.Environ(), probeEnv+"=1")
	output, err := probe.CombinedOutput()
	var exitError *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("forced exit failed: %v, timeout=%v, output=%s", err, ctx.Err(), output)
	}
}
