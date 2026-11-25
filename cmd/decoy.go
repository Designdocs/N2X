package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Designdocs/N2X/common/websitecert"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/decoy"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	decoyHTTPSListenEnvironment = decoy.HTTPSListenEnvironment
	decoyHTTPSCertEnvironment   = "N2X_ARTX_DECOY_HTTPS_CERT_FILE"
	decoyHTTPSKeyEnvironment    = "N2X_ARTX_DECOY_HTTPS_KEY_FILE"
)

var (
	decoyListenAddress      string
	decoyProfile            string
	decoyHTTPSListenAddress string
	decoyHTTPSCertFile      string
	decoyHTTPSKeyFile       string
)

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
	decoyServeCommand.Flags().StringVar(
		&decoyProfile,
		"profile",
		"",
		"default page profile: balanced, web, media or realtime",
	)
	decoyServeCommand.Flags().StringVar(
		&decoyHTTPSListenAddress, "https-listen", "",
		"optional loopback HTTPS address (uses managed certificates by default; default address with manual files: "+decoy.DefaultHTTPSListenAddress+")",
	)
	decoyServeCommand.Flags().StringVar(&decoyHTTPSCertFile, "https-cert-file", "", "HTTPS certificate chain in PEM format")
	decoyServeCommand.Flags().StringVar(&decoyHTTPSKeyFile, "https-key-file", "", "HTTPS private key in PEM format")
	decoyCommand.AddCommand(&decoyServeCommand)
	command.AddCommand(&decoyCommand)
}

func resolveDecoyListen(flagValue string) string {
	if address := decoySetting(flagValue, decoy.ListenAddressEnvironment); address != "" {
		return address
	}
	return decoy.DefaultListenAddress
}

func decoySetting(flagValue, envName string) string {
	if value := strings.TrimSpace(flagValue); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func decoyHTTPSConfig(profile string) *decoy.Config {
	address := decoySetting(decoyHTTPSListenAddress, decoyHTTPSListenEnvironment)
	certFile := decoySetting(decoyHTTPSCertFile, decoyHTTPSCertEnvironment)
	keyFile := decoySetting(decoyHTTPSKeyFile, decoyHTTPSKeyEnvironment)
	if address == "" && certFile == "" && keyFile == "" {
		return nil
	}
	if address == "" {
		address = decoy.DefaultHTTPSListenAddress
	}
	files := &decoy.TLSFiles{CertificateFile: certFile, KeyFile: keyFile}
	if certFile == "" && keyFile == "" {
		certificates := websitecert.New(conf.ManagedCertificateDirectory, "", "")
		files.GetCertificate = certificates.GetCertificate
	}
	return &decoy.Config{
		ListenAddress:  address,
		DefaultProfile: profile,
		TLS:            files,
	}
}

func decoyServe(command *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	profile := strings.TrimSpace(decoyProfile)
	return runDecoyServer(ctx, resolveDecoyListen(decoyListenAddress), profile, decoyHTTPSConfig(profile))
}

func runDecoyServer(ctx context.Context, listenAddress string, defaultProfile string, httpsConfig *decoy.Config) error {
	server, err := decoy.NewServer(decoy.Config{
		ListenAddress:  listenAddress,
		DefaultProfile: defaultProfile,
	})
	if err != nil {
		return err
	}

	if httpsConfig != nil {
		https, err := decoy.NewServer(*httpsConfig)
		if err != nil {
			log.WithError(err).Error("Start companion HTTPS website failed")
		} else {
			httpsContext, cancelHTTPS := context.WithCancel(ctx)
			httpsDone := make(chan struct{})
			go func() {
				defer close(httpsDone)
				log.WithField("listen", httpsConfig.ListenAddress).Info("Companion HTTPS website listening")
				if err := serveDecoy(httpsContext, https); err != nil {
					log.WithError(err).Error("Serve companion HTTPS website failed")
				}
			}()
			defer func() {
				cancelHTTPS()
				<-httpsDone
			}()
		}
	}
	return serveDecoy(ctx, server)
}

func serveDecoy(ctx context.Context, server *decoy.Server) error {
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
