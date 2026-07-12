package decoy

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"time"
)

const DefaultListenAddress = "127.0.0.1:60443"

const maxHeaderBytes = 16 << 10

//go:embed assets
var embeddedAssets embed.FS

type Config struct {
	ListenAddress string
}

type Server struct {
	httpServer *http.Server
	listener   net.Listener
}

func ValidateListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must use a numeric loopback IP")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen address must use a port between 1 and 65535")
	}

	return nil
}

func NewServer(config Config) (*Server, error) {
	address := config.ListenAddress
	if address == "" {
		address = DefaultListenAddress
	}
	if err := ValidateListenAddress(address); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on configured address: %w", err)
	}

	return &Server{
		httpServer: &http.Server{
			Addr:              address,
			Handler:           newHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    maxHeaderBytes,
		},
		listener: listener,
	}, nil
}

func (server *Server) Serve() error {
	err := server.httpServer.Serve(server.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (server *Server) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

func newHandler() http.Handler {
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic("embedded service assets are unavailable")
	}

	handler := &assetHandler{assets: assets}
	return http.HandlerFunc(handler.serveHTTP)
}

type assetHandler struct {
	assets fs.FS
}

func (handler *assetHandler) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	switch request.URL.Path {
	case "/":
		handler.serveAsset(response, request, "index.html", "text/html; charset=utf-8", http.StatusOK)
	case "/assets/site.css":
		handler.serveAsset(response, request, "site.css", "text/css; charset=utf-8", http.StatusOK)
	case "/robots.txt":
		handler.serveAsset(response, request, "robots.txt", "text/plain; charset=utf-8", http.StatusOK)
	case "/favicon.ico":
		response.WriteHeader(http.StatusNoContent)
	default:
		writePlainText(response, request, http.StatusNotFound, "Not Found\n")
	}
}

func writePlainText(response http.ResponseWriter, request *http.Request, status int, body string) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = response.Write([]byte(body))
}

func (handler *assetHandler) serveAsset(
	response http.ResponseWriter,
	request *http.Request,
	name string,
	contentType string,
	status int,
) {
	content, err := fs.ReadFile(handler.assets, name)
	if err != nil {
		http.Error(response, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = response.Write(content)
}
