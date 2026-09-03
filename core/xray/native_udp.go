package xray

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/qlog"
	log "github.com/sirupsen/logrus"
)

type nativeUDPService struct {
	server     *http3.Server
	packetConn net.PacketConn
}

type nativeUDPState struct {
	RequestedMode  string
	ActiveMode     string
	ListenerReady  bool
	CleanupFailure uint64
	CleanupMillis  uint64
	LastErrorCode  string
	LastErrorUnix  int64
}

func (c *Xray) startNativeUDP(tag string, info *panel.NodeInfo, options *conf.Options) (returnErr error) {
	requestedMode := "compat"
	if info != nil && info.ArtX != nil && info.ArtX.UDPMode == "native" {
		requestedMode = "native"
	}
	c.nativeUDPMu.Lock()
	c.ensureNativeUDPStateMapLocked()
	c.nativeUDPState[tag] = &nativeUDPState{RequestedMode: requestedMode, ActiveMode: "compat"}
	c.nativeUDPMu.Unlock()
	if !artXNativeUDPEnabled(info) {
		return nil
	}
	c.nativeUDPMu.Lock()
	c.nativeUDPState[tag] = &nativeUDPState{RequestedMode: "native", ActiveMode: "disabled"}
	c.nativeUDPMu.Unlock()
	defer func() {
		if returnErr != nil {
			c.recordNativeUDPError(tag, "native_listener_start_failed")
		}
	}()
	artXServer, err := c.artXInbound(tag)
	if err != nil {
		return err
	}
	handler, err := artXServer.NewNativeUDPHandler(c.dispatcher, tag)
	if err != nil {
		return err
	}
	packetConn, err := net.ListenPacket("udp", net.JoinHostPort(options.ListenIP, strconv.Itoa(info.Common.ServerPort)))
	if err != nil {
		return err
	}
	http3Server := &http3.Server{
		TLSConfig:       artXServer.NativeUDPTLSConfig(),
		QUICConfig:      &quic.Config{EnableDatagrams: true, Tracer: qlog.DefaultConnectionTracer},
		Handler:         handler,
		EnableDatagrams: true,
	}
	service := &nativeUDPService{server: http3Server, packetConn: packetConn}
	c.nativeUDPMu.Lock()
	if _, exists := c.nativeUDP[tag]; exists {
		c.nativeUDPMu.Unlock()
		_ = packetConn.Close()
		return fmt.Errorf("native UDP service %q already exists", tag)
	}
	c.nativeUDP[tag] = service
	c.nativeUDPState[tag] = &nativeUDPState{
		RequestedMode: "native",
		ActiveMode:    "native",
		ListenerReady: true,
	}
	c.nativeUDPMu.Unlock()
	go func() {
		if err := http3Server.Serve(packetConn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			c.recordNativeUDPError(tag, "native_listener_stopped")
			log.WithError(err).WithField("tag", tag).Error("native UDP service stopped")
		}
	}()
	return nil
}

func (c *Xray) stopNativeUDP(tag string) error {
	startedAt := time.Now()
	c.nativeUDPMu.Lock()
	service := c.nativeUDP[tag]
	delete(c.nativeUDP, tag)
	c.nativeUDPMu.Unlock()
	if service == nil {
		c.recordNativeUDPCleanup(tag, 0, nil)
		return nil
	}
	err := errors.Join(service.server.Close(), service.packetConn.Close())
	c.recordNativeUDPCleanup(tag, time.Since(startedAt), err)
	return err
}

func (c *Xray) closeNativeUDP() error {
	c.nativeUDPMu.Lock()
	c.ensureNativeUDPStateMapLocked()
	services := c.nativeUDP
	c.nativeUDP = make(map[string]*nativeUDPService)
	c.nativeUDPMu.Unlock()
	var closeErrors []error
	for tag, service := range services {
		startedAt := time.Now()
		err := errors.Join(service.server.Close(), service.packetConn.Close())
		closeErrors = append(closeErrors, err)
		c.recordNativeUDPCleanup(tag, time.Since(startedAt), err)
	}
	return errors.Join(closeErrors...)
}

func (c *Xray) recordNativeUDPError(tag, code string) {
	c.nativeUDPMu.Lock()
	defer c.nativeUDPMu.Unlock()
	c.ensureNativeUDPStateMapLocked()
	state := c.nativeUDPState[tag]
	if state == nil {
		state = &nativeUDPState{RequestedMode: "native", ActiveMode: "disabled"}
		c.nativeUDPState[tag] = state
	}
	state.ActiveMode = "disabled"
	state.ListenerReady = false
	state.LastErrorCode = code
	state.LastErrorUnix = time.Now().Unix()
}

func (c *Xray) recordNativeUDPCleanup(tag string, elapsed time.Duration, cleanupErr error) {
	c.nativeUDPMu.Lock()
	defer c.nativeUDPMu.Unlock()
	c.ensureNativeUDPStateMapLocked()
	state := c.nativeUDPState[tag]
	if state == nil {
		state = &nativeUDPState{RequestedMode: "native"}
		c.nativeUDPState[tag] = state
	}
	state.ActiveMode = "disabled"
	state.ListenerReady = false
	state.CleanupMillis = uint64(elapsed.Milliseconds())
	if cleanupErr != nil {
		state.CleanupFailure++
		state.LastErrorCode = "native_cleanup_failed"
		state.LastErrorUnix = time.Now().Unix()
	}
}

func (c *Xray) nativeUDPStatus(tag string) nativeUDPState {
	c.nativeUDPMu.Lock()
	defer c.nativeUDPMu.Unlock()
	if state := c.nativeUDPState[tag]; state != nil {
		return *state
	}
	return nativeUDPState{}
}

func (c *Xray) ensureNativeUDPStateMapLocked() {
	if c.nativeUDPState == nil {
		c.nativeUDPState = make(map[string]*nativeUDPState)
	}
}
