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
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const DefaultListenAddress = "127.0.0.1:60443"

const maxHeaderBytes = 16 << 10

const profileQueryParameter = "profile"

type contentProfile string

const (
	contentProfileBalanced contentProfile = "balanced"
	contentProfileWeb      contentProfile = "web"
	contentProfileMedia    contentProfile = "media"
	contentProfileRealtime contentProfile = "realtime"
)

//go:embed assets
var embeddedAssets embed.FS

type Config struct {
	ListenAddress string
	// DefaultProfile names the page served when a request does not select one
	// itself. Empty means consult ProfileEnvironment, then fall back to
	// balanced.
	DefaultProfile string
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

	profile, err := resolveConfiguredProfile(config.DefaultProfile)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on configured address: %w", err)
	}

	return newServer(listener, profile), nil
}

// newServer wires the HTTP stack onto an already bound listener.
//
// The handler is wrapped in h2c because Xray splices raw, TLS-terminated bytes
// straight to this port. Inbound TLS advertises "h2" and "http/1.1", so a
// browser that picks h2 delivers cleartext HTTP/2 frames here; an HTTP/1.1-only
// listener would reject the preface and the browser would see a protocol error
// instead of a page.
func newServer(listener net.Listener, defaultProfile contentProfile) *Server {
	handler := h2c.NewHandler(newHandler(defaultProfile), &http2.Server{
		IdleTimeout:      30 * time.Second,
		MaxReadFrameSize: maxHeaderBytes,
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              listener.Addr().String(),
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			// ReadTimeout and WriteTimeout are deliberately left unset: the h2c
			// handler hijacks the connection for the lifetime of the HTTP/2
			// session, and a whole-connection deadline would tear down long
			// lived multiplexed streams mid-response.
			IdleTimeout:    30 * time.Second,
			MaxHeaderBytes: maxHeaderBytes,
		},
		listener: listener,
	}
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

func newHandler(defaultProfile contentProfile) http.Handler {
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic("embedded service assets are unavailable")
	}

	handler := &assetHandler{assets: assets, defaultProfile: defaultProfile}
	return http.HandlerFunc(handler.serveHTTP)
}

type assetHandler struct {
	assets         fs.FS
	defaultProfile contentProfile
}

func (handler *assetHandler) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	switch request.URL.Path {
	case "/":
		handler.serveAsset(response, request, handler.pageAssetName(request), "text/html; charset=utf-8", http.StatusOK)
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

// pageAssetName picks the page for a request. An explicit, recognised profile
// query wins; anything else (absent, empty or unknown) gets the configured
// default. Fallback traffic from a browser always lands in the latter case,
// since the browser asks for "/" with no query of its own.
func (handler *assetHandler) pageAssetName(request *http.Request) string {
	if profile, ok := parseContentProfile(request.URL.Query().Get(profileQueryParameter)); ok {
		return string(profile) + ".html"
	}
	return string(handler.defaultProfile) + ".html"
}

func parseContentProfile(value string) (contentProfile, bool) {
	switch profile := contentProfile(strings.ToLower(strings.TrimSpace(value))); profile {
	case contentProfileBalanced, contentProfileWeb, contentProfileMedia, contentProfileRealtime:
		return profile, true
	default:
		return "", false
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
