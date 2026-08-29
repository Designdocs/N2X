package panel

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"

	"github.com/sirupsen/logrus"

	"github.com/Designdocs/N2X/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	NodeType         string
	NodeId           int
	etagMu           sync.Mutex
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
	aliveMu          sync.Mutex
	aliveUpdate      func(map[int]int)
	kickedUpdate     func(map[int]map[string]int64)

	// wsCfg is retained so Start() can spawn the driver lazily after the
	// owning controller has been fully constructed.
	wsCfg conf.WebSocketConfig
	ws    *wsDriver
	wsMu  sync.Mutex

	// apiSuccess / apiFailure are incremented from the resty middleware so
	// the metrics task can report panel-API health to the admin popup.
	apiSuccess atomic.Int64
	apiFailure atomic.Int64
}

func New(c *conf.ApiConfig) (*Client, error) {
	var client *resty.Client
	if c.APISendIP != "" {
		client = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {
		client = resty.New()
	}
	client.SetRetryCount(3)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	// Build the client first so we can hand its address to the success /
	// error hooks. The closures only ever read counters via atomic helpers
	// so capturing the pointer here is goroutine-safe.
	cli := &Client{
		client:    client,
		Token:     c.Key,
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		NodeType:  c.NodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
		wsCfg:     c.WebSocket,
	}
	client.OnAfterResponse(func(_ *resty.Client, resp *resty.Response) error {
		if resp != nil && resp.StatusCode() >= 200 && resp.StatusCode() < 400 {
			cli.apiSuccess.Add(1)
		} else {
			cli.apiFailure.Add(1)
		}
		return nil
	})
	// OnError fires for transport-level failures (DNS/TLS/timeout/etc) where
	// OnAfterResponse may not run. Increment failures here so the popup
	// reflects connectivity issues, not just HTTP error codes.
	client.OnError(func(_ *resty.Request, _ error) {
		cli.apiFailure.Add(1)
	})
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case "v2ray":
		c.NodeType = "vmess"
	case
		"anytls",
		"artx",
		"vmess",
		"trojan",
		"shadowsocks",
		"vless",
		// Panels expose a single "hysteria" node type and pick the generation
		// with a version field; "hysteria2" is accepted here because it is the
		// name operators expect and X-Board aliases it back to "hysteria".
		// GetNodeInfo resolves which one to actually serve.
		"hysteria",
		"hysteria2",
		"tuic",
		"shadowtls",
		"naive":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": c.NodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	cli.NodeType = c.NodeType
	return cli, nil
}

// APIStats returns the cumulative panel-API call counters used by the
// metrics task. Reads are lock-free.
func (c *Client) APIStats() (success, failure int64) {
	return c.apiSuccess.Load(), c.apiFailure.Load()
}

// SetAliveUpdateHook lets the node controller consume real-time device-state
// pushes from the panel without making the panel package depend on limiter.
func (c *Client) SetAliveUpdateHook(hook func(map[int]int)) {
	c.aliveMu.Lock()
	c.aliveUpdate = hook
	c.aliveMu.Unlock()
}

// WebSocketEnabled exposes the operator-configured opt-in flag so the
// metrics task can decide whether the popup should render the WS row.
func (c *Client) WebSocketEnabled() bool {
	return c.wsCfg.Enabled
}

// WebSocketConnected reports whether the WS driver currently has a live
// session to the panel.
func (c *Client) WebSocketConnected() bool {
	return c.wsConnected()
}

// StartWebSocket spawns the optional WebSocket driver if WebSocket.Enabled
// is set in config. When disabled the function is a no-op. Safe to call at
// most once per Client; invoked by the node bootstrap after the HTTP client
// is confirmed working.
func (c *Client) StartWebSocket() {
	if !c.wsCfg.Enabled {
		return
	}
	c.wsMu.Lock()
	defer c.wsMu.Unlock()
	if c.ws != nil {
		return
	}

	wsURL := c.wsCfg.URL
	if wsURL == "" {
		derived, err := deriveWSURL(c.APIHost)
		if err != nil {
			logrus.WithError(err).
				WithField("component", "panel-ws").
				WithField("node_id", c.NodeId).
				Warn("cannot derive ws url from ApiHost; driver disabled")
			return
		}
		wsURL = derived
	}

	driver, err := newWSDriver(wsDriverConfig{
		URL:      wsURL,
		NodeID:   c.NodeId,
		NodeType: c.NodeType,
		Token:    c.Token,
		Debug:    c.wsCfg.Debug,
		Hooks: wsDriverHooks{
			OnSyncConfig:  c.invalidateNodeInfoCache,
			OnSyncUsers:   c.invalidateUserListCache,
			OnSyncDevices: c.onSyncDevices,
			OnSyncKick:    c.onSyncKick,
			OnAuthSuccess: c.onAuthSuccess,
		},
	})
	if err != nil {
		logrus.WithError(err).
			WithField("component", "panel-ws").
			WithField("node_id", c.NodeId).
			Warn("ws driver init failed; running HTTP-only")
		return
	}
	c.ws = driver
	driver.Start()
}

// StopWebSocket tears down the driver if present. Idempotent.
func (c *Client) StopWebSocket() {
	c.wsMu.Lock()
	driver := c.ws
	c.ws = nil
	c.wsMu.Unlock()
	if driver != nil {
		driver.Stop()
	}
}

// wsConnected is a convenience for call sites that want to decide between
// WS-first and HTTP-only code paths.
func (c *Client) wsConnected() bool {
	c.wsMu.Lock()
	driver := c.ws
	c.wsMu.Unlock()
	return driver != nil && driver.Connected()
}

// wsSend pipes an event through the driver if one is running. Returns an
// error (handled the same as "not connected") when no driver exists.
func (c *Client) wsSend(event string, data any) error {
	c.wsMu.Lock()
	driver := c.ws
	c.wsMu.Unlock()
	if driver == nil {
		return errors.New("ws driver not running")
	}
	return driver.Send(event, data)
}

// invalidateNodeInfoCache clears the HTTP ETag state so the next GetNodeInfo
// call bypasses the 304 shortcut. Called when the panel pushes sync.config.
func (c *Client) invalidateNodeInfoCache() {
	c.etagMu.Lock()
	c.nodeEtag = ""
	c.responseBodyHash = ""
	c.etagMu.Unlock()
	logrus.WithField("component", "panel-ws").
		WithField("node_id", c.NodeId).
		Debug("invalidated node info cache")
}

// invalidateUserListCache is the sync.users counterpart.
func (c *Client) invalidateUserListCache() {
	c.etagMu.Lock()
	c.userEtag = ""
	c.etagMu.Unlock()
	logrus.WithField("component", "panel-ws").
		WithField("node_id", c.NodeId).
		Debug("invalidated user list cache")
}

// onSyncDevices consumes X-Board's {users: {uid: [ip...]}} snapshot and
// updates the alive counters used by the device limiter.
func (c *Client) onSyncDevices(raw json.RawMessage) {
	alive, err := decodeDeviceAliveMap(raw)
	if err != nil {
		logrus.WithError(err).
			WithField("component", "panel-ws").
			WithField("node_id", c.NodeId).
			Warn("ws sync.devices decode failed")
		return
	}
	c.applyAliveMap(alive)
	c.applyKickedMap(decodeKickedEnvelope(raw))
	logrus.WithField("component", "panel-ws").
		WithField("node_id", c.NodeId).
		WithField("users", len(alive)).
		Info("ws sync.devices applied")
}

// onSyncKick consumes the panel's kick broadcast ({kicked: {uid: {ip: ttl}}})
// so a user-initiated device kick takes effect within milliseconds instead of
// waiting for the next alivelist poll.
func (c *Client) onSyncKick(raw json.RawMessage) {
	kicked := decodeKickedEnvelope(raw)
	if len(kicked) == 0 {
		return
	}
	c.applyKickedMap(kicked)
	logrus.WithField("component", "panel-ws").
		WithField("node_id", c.NodeId).
		WithField("users", len(kicked)).
		Info("ws sync.kick applied")
}

// decodeKickedEnvelope extracts the optional {kicked: {uid: {ip: ttl}}} block
// shared by alivelist responses, sync.devices pushes, and sync.kick events.
func decodeKickedEnvelope(raw json.RawMessage) map[int]map[string]int64 {
	var envelope struct {
		Kicked map[int]map[string]int64 `json:"kicked"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil
	}
	return envelope.Kicked
}

// SetKickedUpdateHook lets the node controller consume kick updates without
// making the panel package depend on limiter.
func (c *Client) SetKickedUpdateHook(hook func(map[int]map[string]int64)) {
	c.aliveMu.Lock()
	c.kickedUpdate = hook
	c.aliveMu.Unlock()
}

func (c *Client) applyKickedMap(kicked map[int]map[string]int64) {
	if len(kicked) == 0 {
		return
	}

	c.aliveMu.Lock()
	hook := c.kickedUpdate
	c.aliveMu.Unlock()

	if hook != nil {
		hook(kicked)
	}
}

// onAuthSuccess runs once after each successful handshake. We proactively
// request the current device state so a just-restarted node picks up the
// limiter table without waiting for the periodic push.
func (c *Client) onAuthSuccess(nodeID int) {
	if err := c.wsSend("request.devices", nil); err != nil {
		logrus.WithError(err).
			WithField("component", "panel-ws").
			WithField("node_id", nodeID).
			Debug("request.devices on auth.success failed")
	}
}

func (c *Client) applyAliveMap(alive map[int]int) {
	snapshot := copyAliveMap(alive)

	c.aliveMu.Lock()
	if c.AliveMap == nil {
		c.AliveMap = &AliveMap{}
	}
	c.AliveMap.Alive = snapshot
	hook := c.aliveUpdate
	c.aliveMu.Unlock()

	if hook != nil {
		hook(copyAliveMap(snapshot))
	}
}

func (c *Client) cachedAliveMap() map[int]int {
	c.aliveMu.Lock()
	defer c.aliveMu.Unlock()
	if c.AliveMap == nil {
		return map[int]int{}
	}
	return copyAliveMap(c.AliveMap.Alive)
}
