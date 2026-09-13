package cmd

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/spf13/cobra"
)

var (
	checkConfigPath string
	checkEnvFile    string
)

var checkCommand = cobra.Command{
	Use:   "check",
	Short: "Validate the config file without starting anything",
	Long: "Validate the whole config file the same way server does before it starts: " +
		"syntax, unknown keys, values, referenced files and certificate settings.",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		loadEnvFile(checkConfigPath, checkEnvFile, false)
		return checkConfig(checkConfigPath, cmd.OutOrStdout())
	},
}

func init() {
	checkCommand.Flags().StringVarP(&checkConfigPath, "config", "c", "/etc/N2X/config.json", "config file path")
	checkCommand.Flags().StringVarP(&checkEnvFile, "env-file", "e", "", "env file path")
	command.AddCommand(&checkCommand)
}

// checkConfig writes every problem in the config file to out and returns an
// error if there is any. Warnings are written too but do not fail the check.
func checkConfig(path string, out io.Writer) error {
	c, err := loadConfig(path)
	if err != nil {
		var validationErr *conf.ValidationError
		if !errors.As(err, &validationErr) {
			return err
		}
		fmt.Fprintln(out, validationErr.Error())
		return errors.New("config check failed")
	}
	if len(c.Warnings) == 0 {
		fmt.Fprintf(out, "OK: %s is valid\n", path)
		return nil
	}
	for _, warning := range c.Warnings {
		fmt.Fprintf(out, "WARNING: %s\n", warning)
	}
	fmt.Fprintf(out, "OK: %s is valid, with %d warning(s)\n", path, len(c.Warnings))
	return nil
}

// loadConfig loads and validates the config file against the cores compiled
// into this binary.
func loadConfig(path string) (*conf.Conf, error) {
	return conf.LoadValidated(path, validateOptions())
}

func validateOptions() conf.ValidateOptions {
	coreTypes := vCore.RegisteredCore()
	slices.Sort(coreTypes)
	return conf.ValidateOptions{CoreTypes: coreTypes}
}
