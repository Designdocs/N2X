package panel

import (
	"fmt"
	"strings"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList() ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	c.etagMu.Lock()
	currentEtag := c.userEtag
	c.etagMu.Unlock()
	r, err := c.client.R().
		SetHeader("If-None-Match", currentEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	userlist := &UserListBody{}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	c.etagMu.Lock()
	c.userEtag = r.Header().Get("ETag")
	c.etagMu.Unlock()
	return userlist.Users, nil
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive() (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil || r == nil || r.StatusCode() >= 399 {
		return c.cachedAliveMap(), nil
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		return c.cachedAliveMap(), nil
	}
	defer r.RawResponse.Body.Close()
	aliveMap := &AliveMap{}
	if err := json.Unmarshal(r.Body(), aliveMap); err != nil {
		fmt.Printf("unmarshal user alive list error: %s", err)
		return c.cachedAliveMap(), nil
	}
	if aliveMap.Alive == nil {
		aliveMap.Alive = make(map[int]int)
	}
	c.applyAliveMap(aliveMap.Alive)

	return c.cachedAliveMap(), nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	const path = "/api/v1/server/UniProxy/push"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	// WS path: "report.devices" with the same {uid: [ips...]} payload.
	if c.wsConnected() {
		if err := c.wsSend("report.devices", data); err == nil {
			return nil
		}
	}
	const path = "/api/v1/server/UniProxy/alive"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)

	if err != nil {
		return err
	}

	return nil
}

// NodeStatus is the payload reported to X-Board's /UniProxy/status endpoint.
// All totals/used values are in bytes; Cpu is a percentage in [0, 100].
//
// IMPORTANT: This payload is *only* delivered over HTTP. The WebSocket event
// `node.status` is reserved for NodeMetrics — feeding the cpu/mem/swap/disk
// shape into it would cause X-Board's NodeEventHandlers::handleNodeStatus to
// call ServerService::updateMetrics with mismatched fields, polluting the
// METRICS cache with zeros for uptime/goroutines/etc.
type NodeStatus struct {
	Cpu  float64       `json:"cpu"`
	Mem  NodeStatusMem `json:"mem"`
	Swap NodeStatusMem `json:"swap"`
	Disk NodeStatusMem `json:"disk"`
}

type NodeStatusMem struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// ReportNodeStatus pushes the cpu/mem/swap/disk load snapshot to the panel
// over HTTP. Matches the schema validated by UniProxyController::status in
// X-Board — the only legacy V1 path that accepts it.
func (c *Client) ReportNodeStatus(status *NodeStatus) error {
	const path = "/api/v1/server/UniProxy/status"
	r, err := c.client.R().
		SetBody(status).
		ForceContentType("application/json").
		Post(path)
	if err = c.checkResponse(r, path, err); err != nil {
		return fmt.Errorf("report node status: %w", err)
	}
	return nil
}

// NodeMetrics mirrors the shape consumed by X-Board's
// ServerService::updateMetrics. Each sub-struct uses the exact JSON keys
// that the admin frontend (resources/admin) reads via dotted access — e.g.
// `metrics.load.load5`, `metrics.api.success`, `metrics.ws.connected`. If
// any of these are sent as arrays or unkeyed maps the popup hides the row.
//
// Every field is optional from the panel's point of view (zeroes are
// accepted), so the agent can fill what it knows and leave the rest empty
// without breaking validation.
type NodeMetrics struct {
	Uptime            int64               `json:"uptime"`
	Goroutines        int                 `json:"goroutines"`
	ActiveConnections int                 `json:"active_connections"`
	TotalConnections  int                 `json:"total_connections"`
	TotalUsers        int                 `json:"total_users"`
	ActiveUsers       int                 `json:"active_users"`
	InboundSpeed      int64               `json:"inbound_speed"`
	OutboundSpeed     int64               `json:"outbound_speed"`
	CPUPerCore        []float64           `json:"cpu_per_core"`
	Load              *NodeMetricsLoad    `json:"load,omitempty"`
	SpeedLimiter      *NodeMetricsLimiter `json:"speed_limiter,omitempty"`
	GC                *NodeMetricsGC      `json:"gc,omitempty"`
	API               *NodeMetricsAPI     `json:"api,omitempty"`
	WS                *NodeMetricsWS      `json:"ws,omitempty"`
	Limits            *NodeMetricsLimits  `json:"limits,omitempty"`
	ArtX              *NodeMetricsArtX    `json:"artx,omitempty"`
	KernelStatus      bool                `json:"kernel_status"`
}

// NodeMetricsArtX carries privacy-safe native ArtX protocol counters. It
// contains no user, address, credential, or payload dimensions.
type NodeMetricsArtX struct {
	AuthenticationSuccess int `json:"authentication_success"`
	AuthenticationFailure int `json:"authentication_failure"`
	ReplayRejected        int `json:"replay_rejected"`
	FallbackHits          int `json:"fallback_hits"`
	FallbackErrors        int `json:"fallback_errors"`
}

// NodeMetricsLoad maps to `metrics.load.{load1,load5,load15}` on the
// frontend; the popup specifically renders `load.load5.toFixed(2)`.
type NodeMetricsLoad struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// NodeMetricsAPI tracks panel-API call counters surfaced as the lightning
// row "success/failure". The frontend pulses red when failure > 0.
type NodeMetricsAPI struct {
	Success int64 `json:"success"`
	Failure int64 `json:"failure"`
}

// NodeMetricsWS reports the WebSocket driver state. The frontend only
// renders the WS-OK/WS-ERR row when Enabled is true.
type NodeMetricsWS struct {
	Enabled   bool `json:"enabled"`
	Connected bool `json:"connected"`
}

// NodeMetricsGC carries Go GC pause info. Optional — the frontend only
// appends "(Xms)" after kernel_status when last_pause_ms is set.
type NodeMetricsGC struct {
	LastPauseMs float64 `json:"last_pause_ms"`
}

// NodeMetricsLimiter reports active speed-limiting state. has_limits gates
// the destructive "X Limit" row; limited_users is the count shown.
type NodeMetricsLimiter struct {
	HasLimits    bool `json:"has_limits"`
	LimitedUsers int  `json:"limited_users"`
}

// NodeMetricsLimits is the device-limit event counter. Falls back path for
// the Limit row when speed_limiter has nothing to report.
type NodeMetricsLimits struct {
	DeviceLimitEvents int `json:"device_limit_events"`
}

// ReportNodeMetrics pushes the rich runtime metrics to the panel. Preferred
// transport is the WebSocket `node.status` event because X-Board handles it
// inline (NodeEventHandlers::handleNodeStatus → updateMetrics) — that's the
// same path the official Xboard-Node uses to populate the admin popup.
//
// HTTP fallback is the V2 unified `/api/v2/server/report` endpoint with
// only the `metrics` field set; the controller treats each section as
// independent so we don't disturb traffic/alive/online/status reporting which
// continues to flow through the existing V1 paths.
//
// Path is intentionally /api/v2/server/report — the route is registered as
// prefix "server" + POST "report" inside the V2 route group (/api/v2).
// An earlier version sent /node/report which 404'd against every panel.
func (c *Client) ReportNodeMetrics(metrics *NodeMetrics) error {
	if c.wsConnected() {
		if err := c.wsSend("node.status", metrics); err == nil {
			return nil
		}
		// fall through to HTTP on error (logged inside wsSend)
	}
	const path = "/api/v2/server/report"
	body := map[string]interface{}{"metrics": metrics}
	r, err := c.client.R().
		SetBody(body).
		ForceContentType("application/json").
		Post(path)
	if err = c.checkResponse(r, path, err); err != nil {
		return fmt.Errorf("report node metrics: %w", err)
	}
	return nil
}
