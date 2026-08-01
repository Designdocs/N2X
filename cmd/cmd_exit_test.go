package cmd

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// runExitProbeEnvironment marks the re-executed test binary that should call
// Run() for real. Observing the process exit code is the only way to test
// os.Exit without terminating the parent test run.
const runExitProbeEnvironment = "N2X_TEST_RUN_EXIT_PROBE"

func runExitProbe(t *testing.T, testName string, arguments ...string) int {
	t.Helper()

	command := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	command.Env = append(os.Environ(), runExitProbeEnvironment+"=1")
	command.Args = append(command.Args, "--")
	command.Args = append(command.Args, arguments...)

	output, err := command.CombinedOutput()
	t.Logf("probe output:\n%s", output)

	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	t.Fatalf("run probe: %v", err)
	return -1
}

// A command that fails must exit non-zero. Without it a bad configuration looks
// like a clean shutdown: systemd reports no failure and Restart=always quietly
// loops instead of surfacing the error.
func TestRunExitsNonZeroOnCommandFailure(t *testing.T) {
	if os.Getenv(runExitProbeEnvironment) == "1" {
		// A non-loopback listen address is rejected before anything binds.
		os.Args = []string{"N2X", "decoy", "serve", "--listen", "192.0.2.1:60443"}
		Run()
		return
	}

	if code := runExitProbe(t, "TestRunExitsNonZeroOnCommandFailure"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunExitsZeroOnSuccess(t *testing.T) {
	if os.Getenv(runExitProbeEnvironment) == "1" {
		os.Args = []string{"N2X", "version"}
		Run()
		return
	}

	if code := runExitProbe(t, "TestRunExitsZeroOnSuccess"); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}
