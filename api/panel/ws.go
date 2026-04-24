package panel

// WebSocket driver for the X-Board /ws/ endpoint.
//
// Design goals:
//   - Strictly opt-in via ApiConfig.WebSocket.Enabled. Zero behavior change
//     when disabled; rollback is a single config flip.
//   - Sidecar model: the driver never owns authoritative state. HTTP remains
//     the source of truth; WS only accelerates refreshes and carries outbound
//     reports (node.status, report.devices) when connected.
//   - Loud structured logs at every lifecycle edge (dial, auth, event,
//     reconnect) so first-run debugging is cheap. Set WebSocket.Debug=true
//     in config for per-message traces.
//   - Survives panel downtime: exponential backoff reconnect, never panics,
//     never blocks the caller. If the socket is down, Send() returns an
//     error and the caller falls back to HTTP.
//
// Protocol reference: app/WebSocket/NodeWorker.php +
// app/WebSocket/NodeEventHandlers.php in the X-Board repo.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	wsAuthTimeout         = 10 * time.Second
	wsMinReconnectBackoff = 3 * time.Second
	wsMaxReconnectBackoff = 60 * time.Second
	wsWriteTimeout        = 10 * time.Second
	// X-Board pings every 55s; anything longer than that + tolerance means
	// the socket is dead and we should reconnect. 150s gives ~2.7x margin.
	wsReadTimeout = 150 * time.Second
	// 4 MiB ceiling accommodates sync.users for large fleets without
	// blowing up the gorilla reader.
	wsMaxMessageBytes = 4 * 1024 * 1024
)

// wsEvent is the on-wire envelope shared with X-Board NodeWorker. Data is
// kept as raw JSON so handlers can decode into event-specific shapes lazily.
type wsEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// wsDriverHooks lets the owning panel.Client react to server pushes without
// the driver needing to know about client internals. All hooks are optional.
type wsDriverHooks struct {
	// OnSyncConfig fires when the panel announces a config change. The
	// client should invalidate its config ETag so the next HTTP poll
	// returns fresh data.
	OnSyncConfig func()
	// OnSyncUsers fires when the user roster changes.
	OnSyncUsers func()
	// OnSyncDevices delivers the device-state update from the panel.
	// Payload is the raw {users: ...} block; the client decides how to
	// apply it.
	OnSyncDevices func(raw json.RawMessage)
	// OnAuthSuccess fires once per successful handshake. Useful for
	// one-shot "ask for full state" logic (e.g. request.devices).
	OnAuthSuccess func(nodeID int)
}

// wsDriverConfig is the immutable configuration handed to newWSDriver.
type wsDriverConfig struct {
	URL      string
	NodeID   int
	NodeType string
	Token    string
	Debug    bool
	Hooks    wsDriverHooks
}

// wsDriver owns the lifecycle of a WebSocket session. One driver per panel
// client per node.
type wsDriver struct {
	cfg wsDriverConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connMu    sync.Mutex
	conn      *websocket.Conn
	writeMu   sync.Mutex // serializes writes on the active conn
	connected atomic.Bool

	logFields log.Fields
}

// newWSDriver validates the config and returns an unstarted driver. The
// caller must invoke Start() to kick off the reconnect loop.
func newWSDriver(cfg wsDriverConfig) (*wsDriver, error) {
	if cfg.URL == "" {
		return nil, errors.New("ws driver: empty URL")
	}
	if cfg.Token == "" {
		return nil, errors.New("ws driver: empty token")
	}
	if cfg.NodeID <= 0 {
		return nil, errors.New("ws driver: invalid node id")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &wsDriver{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		logFields: log.Fields{
			"component": "panel-ws",
			"node_id":   cfg.NodeID,
			"node_type": cfg.NodeType,
		},
	}, nil
}

// Start spawns the reconnect loop. Safe to call once; subsequent calls are
// no-ops so wiring it from a service bootstrap path is idempotent.
func (d *wsDriver) Start() {
	d.wg.Add(1)
	go d.runLoop()
	log.WithFields(d.logFields).WithField("url", maskToken(d.cfg.URL)).Info("ws driver started")
}

// Stop cancels the reconnect loop and tears down any active connection.
// Blocks until the background goroutine returns so shutdowns are clean.
func (d *wsDriver) Stop() {
	d.cancel()
	d.closeCurrentConn()
	d.wg.Wait()
	log.WithFields(d.logFields).Info("ws driver stopped")
}

// Connected reports whether there is an authenticated session available for
// outbound sends. Callers should use it as a hint only — the socket can drop
// between the check and the Send.
func (d *wsDriver) Connected() bool { return d.connected.Load() }

// Send serializes a single event to the active socket. Returns an error when
// the socket is not connected or the write fails. Callers should interpret
// the error as "fall back to HTTP".
func (d *wsDriver) Send(event string, data any) error {
	if !d.connected.Load() {
		return errors.New("ws not connected")
	}
	payload, err := json.Marshal(wsEvent{
		Event: event,
		Data:  marshalRaw(data),
	})
	if err != nil {
		return fmt.Errorf("ws marshal %s: %w", event, err)
	}

	d.connMu.Lock()
	conn := d.conn
	d.connMu.Unlock()
	if conn == nil {
		return errors.New("ws not connected")
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return fmt.Errorf("ws set write deadline: %w", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		log.WithFields(d.logFields).WithError(err).Warn("ws write failed, marking disconnected")
		d.markDisconnectedLocked(conn)
		return fmt.Errorf("ws write %s: %w", event, err)
	}
	if d.cfg.Debug {
		log.WithFields(d.logFields).Debugf("ws send %s (%d bytes)", event, len(payload))
	}
	return nil
}

// runLoop keeps one session alive at a time with exponential backoff.
func (d *wsDriver) runLoop() {
	defer d.wg.Done()
	backoff := wsMinReconnectBackoff
	for {
		if d.ctx.Err() != nil {
			return
		}

		log.WithFields(d.logFields).
			WithField("url", maskToken(d.cfg.URL)).
			Info("ws dialing")
		err := d.runSession()
		if d.ctx.Err() != nil {
			return
		}
		if err != nil {
			log.WithFields(d.logFields).
				WithError(err).
				Warnf("ws session ended, retry in %s", backoff)
		} else {
			log.WithFields(d.logFields).Info("ws session ended cleanly, retry soon")
		}

		select {
		case <-d.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > wsMaxReconnectBackoff {
			backoff = wsMaxReconnectBackoff
		}
	}
}

// runSession dials, stores the conn, runs the read pump, and cleans up.
// Any error causes the outer runLoop to back off and retry.
func (d *wsDriver) runSession() error {
	u, err := url.Parse(d.cfg.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	q.Set("token", d.cfg.Token)
	q.Set("node_id", strconv.Itoa(d.cfg.NodeID))
	u.RawQuery = q.Encode()

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = wsAuthTimeout

	conn, resp, err := dialer.DialContext(d.ctx, u.String(), http.Header{
		"User-Agent": []string{"N2X-panel-ws"},
	})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial (status %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("dial: %w", err)
	}
	log.WithFields(d.logFields).Info("ws connected, awaiting auth.success")

	d.connMu.Lock()
	d.conn = conn
	d.connMu.Unlock()
	defer d.markDisconnectedLocked(conn)

	conn.SetReadLimit(wsMaxMessageBytes)
	if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
	})

	// Read pump. X-Board drives the heartbeat via application-level `ping`
	// events, so we do not originate pings from the client side.
	for {
		if d.ctx.Err() != nil {
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second))
			return nil
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
			return fmt.Errorf("refresh read deadline: %w", err)
		}
		if err := d.handleMessage(msg); err != nil {
			// Handler errors are per-message; log and keep the session.
			log.WithFields(d.logFields).WithError(err).Warn("ws handler error")
		}
	}
}

// handleMessage decodes a single envelope and dispatches to a hook.
func (d *wsDriver) handleMessage(raw []byte) error {
	var evt wsEvent
	if err := json.Unmarshal(raw, &evt); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if d.cfg.Debug {
		log.WithFields(d.logFields).Debugf("ws recv %s (%d bytes)", evt.Event, len(raw))
	}

	switch evt.Event {
	case "auth.success":
		d.connected.Store(true)
		log.WithFields(d.logFields).Info("ws authenticated")
		if d.cfg.Hooks.OnAuthSuccess != nil {
			d.cfg.Hooks.OnAuthSuccess(d.cfg.NodeID)
		}

	case "ping":
		return d.Send("pong", map[string]any{"ts": time.Now().Unix()})

	case "sync.config":
		log.WithFields(d.logFields).Info("ws sync.config")
		if d.cfg.Hooks.OnSyncConfig != nil {
			d.cfg.Hooks.OnSyncConfig()
		}

	case "sync.users":
		log.WithFields(d.logFields).Info("ws sync.users")
		if d.cfg.Hooks.OnSyncUsers != nil {
			d.cfg.Hooks.OnSyncUsers()
		}

	case "sync.devices":
		log.WithFields(d.logFields).Info("ws sync.devices")
		if d.cfg.Hooks.OnSyncDevices != nil {
			d.cfg.Hooks.OnSyncDevices(evt.Data)
		}

	case "error":
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(evt.Data, &e)
		log.WithFields(d.logFields).
			WithField("message", e.Message).
			Error("ws server reported error")

	default:
		if d.cfg.Debug {
			log.WithFields(d.logFields).Debugf("ws unhandled event %q", evt.Event)
		}
	}
	return nil
}

// closeCurrentConn is a helper for Stop().
func (d *wsDriver) closeCurrentConn() {
	d.connMu.Lock()
	conn := d.conn
	d.conn = nil
	d.connMu.Unlock()
	d.connected.Store(false)
	if conn != nil {
		_ = conn.Close()
	}
}

// markDisconnectedLocked closes the given conn only if it is still the
// active one, to avoid races between Stop() and runSession()'s defer.
func (d *wsDriver) markDisconnectedLocked(conn *websocket.Conn) {
	d.connMu.Lock()
	if d.conn == conn {
		d.conn = nil
	}
	d.connMu.Unlock()
	d.connected.Store(false)
	if conn != nil {
		_ = conn.Close()
	}
}

// marshalRaw converts arbitrary data to a raw JSON message. Errors collapse
// to a null value so the caller path never panics; the server ignores null
// payloads for informational events like pong.
func marshalRaw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// maskToken redacts the token query parameter so URLs are safe to log.
func maskToken(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Has("token") {
		q.Set("token", "***")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// deriveWSURL converts an HTTP panel base URL into a WebSocket endpoint.
// Explicit WebSocketConfig.URL always wins; this helper is only used when
// the user did not specify one.
func deriveWSURL(apiHost string) (string, error) {
	if apiHost == "" {
		return "", errors.New("empty api host")
	}
	u, err := url.Parse(apiHost)
	if err != nil {
		return "", fmt.Errorf("parse api host: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already a ws url
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	// Append /ws/ if the caller did not already point at a path.
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws/"
	}
	return u.String(), nil
}
