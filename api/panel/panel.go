package panel

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
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

	// wsCfg is retained so Start() can spawn the driver lazily after the
	// owning controller has been fully constructed.
	wsCfg conf.WebSocketConfig
	ws    *wsDriver
	wsMu  sync.Mutex
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
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case "v2ray":
		c.NodeType = "vmess"
	case
		"anytls",
		"vmess",
		"trojan",
		"shadowsocks",
		"vless":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": c.NodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:    client,
		Token:     c.Key,
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		NodeType:  c.NodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
		wsCfg:     c.WebSocket,
	}, nil
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

// onSyncDevices is a minimal sync.devices handler: for now we only log the
// size and rely on the next HTTP /alivelist poll to pick up authoritative
// state. Splitting real-time device handling out of HTTP is a future step.
func (c *Client) onSyncDevices(raw json.RawMessage) {
	var payload struct {
		Users map[string]json.RawMessage `json:"users"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		logrus.WithError(err).
			WithField("component", "panel-ws").
			WithField("node_id", c.NodeId).
			Warn("ws sync.devices decode failed")
		return
	}
	logrus.WithField("component", "panel-ws").
		WithField("node_id", c.NodeId).
		WithField("users", len(payload.Users)).
		Info("ws sync.devices received (HTTP poll authoritative)")
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
