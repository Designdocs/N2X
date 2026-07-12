package cmd

import (
	"errors"
	"reflect"
	"testing"
)

func TestCleanupArtXDecoyServiceIsBestEffort(t *testing.T) {
	var commands []string
	var removedPaths []string
	commandUnavailable := errors.New("command unavailable")
	run := func(command string) (string, error) {
		commands = append(commands, command)
		return "", commandUnavailable
	}
	remove := func(path string) error {
		removedPaths = append(removedPaths, path)
		return commandUnavailable
	}

	cleanupArtXDecoyService(run, remove)

	wantCommands := []string{
		"systemctl stop N2X-artx-decoy",
		"systemctl disable N2X-artx-decoy",
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("cleanup commands = %q, want %q", commands, wantCommands)
	}
	if wantPaths := []string{artXDecoyServiceFile}; !reflect.DeepEqual(removedPaths, wantPaths) {
		t.Fatalf("removed paths = %q, want %q", removedPaths, wantPaths)
	}
}
