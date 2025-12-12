package cmd

import (
	log "github.com/sirupsen/logrus"

	_ "github.com/Designdocs/N2X/core/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "N2X",
}

func Run() {
	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}
