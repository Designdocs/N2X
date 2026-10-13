package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

func TestMemoryRestartUsesAvailableMemory(t *testing.T) {
	for _, tt := range []struct {
		name             string
		total, available uint64
		percent          int
		want             bool
	}{
		{"below", 1000, 101, 90, false},
		{"at threshold", 1000, 100, 90, true},
		{"above", 1000, 99, 90, true},
		{"cache remains available", 1000, 450, 90, false},
		{"unknown", 0, 0, 90, false},
		{"invalid sample", 1000, 1001, 90, false},
		{"disabled", 1000, 0, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := memoryRestartRequired(tt.total, tt.available, tt.percent); got != tt.want {
				t.Fatalf("restart = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryGuardSkipsFailedProbeAndCanBeDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls int
		guard := &memoryGuard{sample: func() (uint64, uint64, error) {
			calls++
			if calls == 1 {
				return 1000, 0, errors.New("probe failed")
			}
			return 1000, 100, nil
		}}
		guard.restartPercent.Store(90)
		signals := make(chan os.Signal, 1)
		result := make(chan error, 1)
		go func() { result <- guard.wait(signals) }()
		time.Sleep(memoryCheckInterval)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("failed probe triggered exit: %v", err)
		default:
		}
		guard.restartPercent.Store(0)
		time.Sleep(memoryCheckInterval)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("disabled guard triggered exit: %v", err)
		default:
		}
		guard.restartPercent.Store(90)
		time.Sleep(memoryCheckInterval)
		if err := <-result; err == nil {
			t.Fatal("expected memory pressure exit")
		}
	})
}

func TestMemoryGuardStopsOnSignal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	guard := &memoryGuard{}
	if err := guard.wait(signals); err != nil {
		t.Fatal(err)
	}
}

func TestMemorySoftLimitRespectsEnvironmentAndRestoresDefault(t *testing.T) {
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })
	guard := &memoryGuard{initialLimit: previous, sample: func() (uint64, uint64, error) { return 1000 << 20, 900 << 20, nil }}
	t.Setenv("GOMEMLIMIT", "")
	guard.configure(conf.MemoryConfig{SoftLimitPercent: 70, RestartPercent: 90})
	if got := debug.SetMemoryLimit(-1); got != 700<<20 {
		t.Fatalf("soft limit = %d, want %d", got, 700<<20)
	}
	guard.configure(conf.MemoryConfig{RestartPercent: 90})
	if got := debug.SetMemoryLimit(-1); got != previous {
		t.Fatalf("disabled limit = %d, want %d", got, previous)
	}
	t.Setenv("GOMEMLIMIT", "500MiB")
	debug.SetMemoryLimit(500 << 20)
	guard.explicitLimit = true
	guard.configure(conf.MemoryConfig{SoftLimitPercent: 70})
	if got := debug.SetMemoryLimit(-1); got != 500<<20 {
		t.Fatalf("explicit limit overwritten: %d", got)
	}
}

func TestMemoryLimitLoadedAfterStartupDoesNotDisableProtection(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	guard := newMemoryGuard()
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })
	guard.sample = func() (uint64, uint64, error) { return 1000 << 20, 900 << 20, nil }
	t.Setenv("GOMEMLIMIT", "500MiB")
	guard.configure(conf.MemoryConfig{SoftLimitPercent: 70})
	if got := debug.SetMemoryLimit(-1); got != 700<<20 {
		t.Fatalf("late environment value disabled soft limit: %d", got)
	}
}

type blockedMemoryLog struct{}

func (blockedMemoryLog) Write([]byte) (int, error) { select {} }

func TestMemoryRestartDeadlineSurvivesBlockedLogging(t *testing.T) {
	const probeEnv = "N2X_TEST_MEMORY_RESTART_PROBE"
	if os.Getenv(probeEnv) == "1" {
		log.SetOutput(blockedMemoryLog{})
		prepareMemoryRestart(&memoryPressure{total: 1000, available: 100, percent: 90}, 50*time.Millisecond)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMemoryRestartDeadlineSurvivesBlockedLogging$")
	probe.Env = append(os.Environ(), probeEnv+"=1")
	output, err := probe.CombinedOutput()
	var exitError *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("forced exit failed: %v, timeout=%v, output=%s", err, ctx.Err(), output)
	}
}
