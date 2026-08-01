package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"

	_ "github.com/Designdocs/N2X/core/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "N2X",
}

// Run executes the CLI and exits non-zero when the command fails.
//
// The exit code matters to the service managers: with a zero status a failed
// start looks like a clean shutdown, so systemd reports no failure and keeps
// restarting the unit without ever marking it failed.
//
// Calling os.Exit here is safe because command.Execute has already returned,
// so every deferred function inside the command handlers has run.
func Run() {
	if err := command.Execute(); err != nil {
		log.WithField("err", err).Error("Execute command failed")
		os.Exit(1)
	}
}
