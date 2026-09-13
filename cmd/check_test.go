package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	validTestConfig = `{
  "Log": {"Level": "info"},
  "Cores": [{"Type": "xray"}],
  "Nodes": [{"Core": "xray", "ApiHost": "https://panel.example.com", "ApiKey": "secret", "NodeID": 1, "NodeType": "vless"}]
}`
	invalidTestConfig = `{
  "Log": {"Level": "info"},
  "Cores": [{"Type": "xray"}],
  "Nodes": [{"Core": "xray", "ApiHost": "https://panel.example.com", "ApiKey": "secret", "NodeID": 1, "NodeTyp": "vless"}]
}`
	// probeConfigEnvironment hands the parent test's config file to the probe.
	probeConfigEnvironment = "N2X_TEST_PROBE_CONFIG"
)

func writeTestConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestCheckConfigAcceptsValidFile(t *testing.T) {
	var out strings.Builder
	path := writeTestConfig(t, validTestConfig)
	if err := checkConfig(path, &out); err != nil {
		t.Fatalf("expected the config to pass, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("expected an OK line, got %q", out.String())
	}
}

func TestCheckConfigListsEveryProblem(t *testing.T) {
	var out strings.Builder
	path := writeTestConfig(t, invalidTestConfig)
	if err := checkConfig(path, &out); err == nil {
		t.Fatal("expected the config to be rejected")
	}
	for _, want := range []string{"Nodes[0].NodeTyp", `did you mean "NodeType"`, "Nodes[0].NodeType"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not mention %q:\n%s", want, out.String())
		}
	}
}

func TestCheckCommandExitCode(t *testing.T) {
	if os.Getenv(runExitProbeEnvironment) == "1" {
		os.Args = []string{"N2X", "check", "-c", os.Getenv(probeConfigEnvironment)}
		Run()
		return
	}
	for name, text := range map[string]string{"valid": validTestConfig, "invalid": invalidTestConfig} {
		t.Setenv(probeConfigEnvironment, writeTestConfig(t, text))
		want := map[string]int{"valid": 0, "invalid": 1}[name]
		if code := runExitProbe(t, "TestCheckCommandExitCode"); code != want {
			t.Errorf("%s config: exit code = %d, want %d", name, code, want)
		}
	}
}

// An invalid config must stop the server before any core or node starts, and
// report the failure to the service manager.
func TestServerRefusesInvalidConfig(t *testing.T) {
	if os.Getenv(runExitProbeEnvironment) == "1" {
		os.Args = []string{"N2X", "server", "-c", os.Getenv(probeConfigEnvironment)}
		Run()
		return
	}
	t.Setenv(probeConfigEnvironment, writeTestConfig(t, invalidTestConfig))
	if code := runExitProbe(t, "TestServerRefusesInvalidConfig"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}
