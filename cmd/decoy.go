package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Designdocs/N2X/decoy"
	"github.com/spf13/cobra"
)

const decoyListenEnvironment = "N2X_ARTX_DECOY_LISTEN"

var decoyListenAddress string

var decoyCommand = cobra.Command{
	Use:   "decoy",
	Short: "Manage the companion web service",
}

var decoyServeCommand = cobra.Command{
	Use:   "serve",
	Short: "Run the companion web service",
	Args:  cobra.NoArgs,
	RunE:  decoyServe,
}

func init() {
	decoyServeCommand.Flags().StringVar(
		&decoyListenAddress,
		"listen",
		"",
		"loopback listen address",
	)
	decoyCommand.AddCommand(&decoyServeCommand)
	command.AddCommand(&decoyCommand)
}

func resolveDecoyListen(flagValue string) string {
	if address := strings.TrimSpace(flagValue); address != "" {
		return address
	}
	if address := strings.TrimSpace(os.Getenv(decoyListenEnvironment)); address != "" {
		return address
	}
	return decoy.DefaultListenAddress
}

func decoyServe(command *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runDecoyServer(ctx, resolveDecoyListen(decoyListenAddress))
}

func runDecoyServer(ctx context.Context, listenAddress string) error {
	server, err := decoy.NewServer(decoy.Config{ListenAddress: listenAddress})
	if err != nil {
		return err
	}

	serveContext, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	shutdownResult := make(chan error, 1)
	go func() {
		<-serveContext.Done()
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		shutdownResult <- server.Shutdown(shutdownContext)
	}()

	serveErr := server.Serve()
	cancelServe()
	shutdownErr := <-shutdownResult
	return errors.Join(serveErr, shutdownErr)
}
