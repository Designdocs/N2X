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
	c.AliveMap = &AliveMap{}
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}

	return c.AliveMap.Alive, nil
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
		return nil
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
// ServerService::updateMetrics. Every field is optional from the panel's
// point of view (zeroes are accepted), so the agent can fill what it knows
// and leave the rest empty without breaking validation.
//
// The panel surfaces these fields in the admin "节点状态" popup via the
// `metrics` accessor on the Server model. Without this payload the popup
// shows uptime/goroutines/users/speeds as empty placeholders even though
// cpu/mem/disk render correctly from the LOAD_STATUS cache.
type NodeMetrics struct {
	Uptime            int64                  `json:"uptime"`
	Goroutines        int                    `json:"goroutines"`
	ActiveConnections int                    `json:"active_connections"`
	TotalConnections  int                    `json:"total_connections"`
	TotalUsers        int                    `json:"total_users"`
	ActiveUsers       int                    `json:"active_users"`
	InboundSpeed      int64                  `json:"inbound_speed"`
	OutboundSpeed     int64                  `json:"outbound_speed"`
	CPUPerCore        []float64              `json:"cpu_per_core"`
	Load              []float64              `json:"load"`
	SpeedLimiter      map[string]interface{} `json:"speed_limiter"`
	GC                map[string]interface{} `json:"gc"`
	API               map[string]interface{} `json:"api"`
	WS                map[string]interface{} `json:"ws"`
	Limits            map[string]interface{} `json:"limits"`
	KernelStatus      bool                   `json:"kernel_status"`
}

// ReportNodeMetrics pushes the rich runtime metrics to the panel. Preferred
// transport is the WebSocket `node.status` event because X-Board handles it
// inline (NodeEventHandlers::handleNodeStatus → updateMetrics) — that's the
// same path the official Xboard-Node uses to populate the admin popup.
//
// HTTP fallback is the V2 unified `/api/v2/server/node/report` endpoint with
// only the `metrics` field set; the controller treats each section as
// independent so we don't disturb traffic/alive/online/status reporting which
// continues to flow through the existing V1 paths.
func (c *Client) ReportNodeMetrics(metrics *NodeMetrics) error {
	if c.wsConnected() {
		if err := c.wsSend("node.status", metrics); err == nil {
			return nil
		}
		// fall through to HTTP on error (logged inside wsSend)
	}
	const path = "/api/v2/server/node/report"
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
