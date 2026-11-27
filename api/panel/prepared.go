package panel

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Designdocs/N2X/conf"
)

// PreparedNode holds the original wire configuration: protocol-specific
// normalisation derives values that cannot round-trip through NodeInfo JSON.
type PreparedNode struct {
	Config         json.RawMessage
	ConfigETag     string
	Users          []UserInfo
	UserETag       string
	UserRevision   int64
	Devices        *AliveMap
	DevicesFetched time.Time
}

func (c *Client) PrepareNode(options *conf.Options) (*PreparedNode, error) {
	var data PreparedNode
	info, err := c.fetchNodeInfo(&data)
	if err != nil {
		return nil, fmt.Errorf("get node config: %w", err)
	}
	if info == nil || info.Common == nil || info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
		return nil, errors.New("node config has no valid listening port")
	}
	cert, err := info.LocalCertConfig(options)
	if err != nil {
		return nil, err
	}
	if info.Security == Tls && cert != nil && cert.CertMode == "file" {
		if _, err := tls.LoadX509KeyPair(cert.CertFile, cert.KeyFile); err != nil {
			return nil, fmt.Errorf("read local TLS certificate: %w", err)
		}
	}
	if info.Snell != nil {
		if err := info.Snell.ValidateListen(options.ListenIP, info.Common.ServerPort); err != nil {
			return nil, err
		}
	}
	data.Users, err = c.GetUserList()
	if err != nil {
		return nil, fmt.Errorf("get user list: %w", err)
	}
	if data.Users == nil || (len(data.Users) == 0 && info.Type != "snell") {
		return nil, errors.New("no usable user list")
	}
	for _, user := range data.Users {
		if user.Id <= 0 || user.Uuid == "" {
			return nil, fmt.Errorf("invalid user record (id %d)", user.Id)
		}
	}
	data.UserETag, data.UserRevision = c.userEtag, c.userExemptionsRevision
	data.DevicesFetched = time.Now()
	data.Devices, err = c.fetchAlive()
	if err != nil {
		return nil, fmt.Errorf("get alive list: %w", err)
	}
	if data.Devices.Alive == nil {
		return nil, errors.New("alive list missing alive counts")
	}
	return &data, nil
}

// RestorePrepared seeds only the first startup. Subsequent HTTP/WS syncs use
// the ordinary client, including conditional requests and device updates.
func (c *Client) RestorePrepared(data *PreparedNode) (*NodeInfo, error) {
	info, err := c.decodeNodeInfo(data.Config, data.ConfigETag, "", 0, 0)
	if err != nil {
		return nil, err
	}
	c.userEtag, c.userExemptionsRevision = data.UserETag, data.UserRevision
	c.applyAliveMap(data.Devices.Alive)
	// The panel sends remaining kick durations in seconds. Time spent
	// staging other nodes must not extend an existing kick.
	elapsed := max(int64(0), int64(time.Since(data.DevicesFetched)/time.Second))
	for _, ips := range data.Devices.Kicked {
		for ip, ttl := range ips {
			ips[ip] = max(int64(0), ttl-elapsed)
		}
	}
	return info, nil
}
