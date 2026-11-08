package xray

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/Designdocs/N2X/common/jsonutil"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/socks"
)

type outboundDefinition struct {
	key    string
	config *core.OutboundHandlerConfig
	live   bool
	dialer string
}

func readOutboundDefinitions(c *conf.XrayConfig) (definitions []outboundDefinition, err error) {
	// Xray's builders can panic on malformed nested protocol settings.
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid Xray outbound settings: %v", recovered)
		}
	}()
	data, err := c.ReadOutboundConfig()
	if err != nil || data == nil {
		return nil, err
	}
	var entries []jsontext.Value
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	definitions = make([]outboundDefinition, 0, len(entries))
	for i, entry := range entries {
		if entry.Kind() != '{' {
			return nil, fmt.Errorf("outbound[%d] must be an object", i)
		}
		var raw coreConf.OutboundDetourConfig
		if err := json.Unmarshal(entry, &raw); err != nil {
			return nil, fmt.Errorf("outbound[%d]: %w", i, err)
		}
		built, err := raw.Build()
		if err != nil {
			return nil, fmt.Errorf("outbound[%d] (%q): %w", i, raw.Tag, err)
		}
		key, err := jsonutil.Canonical(entry)
		if err != nil {
			return nil, fmt.Errorf("outbound[%d]: %w", i, err)
		}
		definition := outboundDefinition{key: string(key), config: built, live: supportsOutboundDrain(&raw)}
		if raw.StreamSetting != nil && raw.StreamSetting.SocketSettings != nil {
			definition.dialer = raw.StreamSetting.SocketSettings.DialerProxy
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func supportsOutboundDrain(raw *coreConf.OutboundDetourConfig) bool {
	if raw.MuxSettings != nil && raw.MuxSettings.Enabled {
		return false
	}
	if stream := raw.StreamSetting; stream != nil && stream.Network != nil {
		network := strings.ToLower(string(*stream.Network))
		if network != "tcp" && network != "raw" {
			return false
		}
	}
	switch strings.ToLower(raw.Protocol) {
	case "socks", "freedom", "direct", "blackhole", "block":
		return true
	case "http":
		// The upstream HTTP/2 connection cache is keyed by address, not
		// handler. A secured transport can reuse the old connection settings.
		return raw.StreamSetting == nil || raw.StreamSetting.Security == "" || strings.EqualFold(raw.StreamSetting.Security, "none")
	default:
		return false
	}
}

func checkOutboundEndpoint(config *core.OutboundHandlerConfig) error {
	proxy, err := config.ProxySettings.GetInstance()
	if err != nil {
		return err
	}
	var server *protocol.ServerEndpoint
	switch proxy := proxy.(type) {
	case *socks.ClientConfig:
		server = proxy.GetServer()
	case *http.ClientConfig:
		server = proxy.GetServer()
	default:
		return nil
	}
	address := server.GetAddress()
	ipLen := len(address.GetIp())
	if server.GetPort() == 0 || (address.GetDomain() == "" && ipLen != 4 && ipLen != 16) {
		return fmt.Errorf("proxy server needs a valid address and nonzero port")
	}
	return nil
}

type createOutbound func(*core.OutboundHandlerConfig) (outbound.Handler, error)

func outboundFactory(server *core.Instance) createOutbound {
	return func(config *core.OutboundHandlerConfig) (handler outbound.Handler, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("invalid outbound settings: %v", recovered)
			}
		}()
		obj, err := core.CreateObject(server, config)
		if err != nil {
			return nil, err
		}
		handler, ok := obj.(outbound.Handler)
		if !ok {
			return nil, fmt.Errorf("unexpected Xray outbound type %T", obj)
		}
		return handler, nil
	}
}

func (m *outboundManager) prepare(definitions []outboundDefinition, create createOutbound, live bool,
	checkRemoved func(map[string]struct{}) error) (finish func(bool), err error) {
	m.mu.Lock()
	var created []outbound.Handler
	defer func() {
		if finish == nil {
			for _, handler := range created {
				_ = handler.Close()
			}
			m.mu.Unlock()
		}
	}()

	old := make(map[string][]outbound.Handler, len(m.custom))
	for _, entry := range m.custom {
		old[entry.key] = append(old[entry.key], entry.handler)
	}
	next := make([]customOutbound, 0, len(definitions))
	tags := make(map[string]struct{}, len(definitions))
	var changed []outboundDefinition
	for _, definition := range definitions {
		tag := definition.config.Tag
		if tag != "" {
			if _, exists := tags[tag]; exists || m.dynamic.GetHandler(tag) != nil {
				return nil, fmt.Errorf("duplicate outbound tag %q", tag)
			}
			tags[tag] = struct{}{}
		}
		if entries := old[definition.key]; len(entries) > 0 {
			next = append(next, customOutbound{definition.key, entries[0]})
			old[definition.key] = entries[1:]
			continue
		}
		if live && !definition.live {
			return nil, fmt.Errorf("outbound %q requires a restart to change this protocol or transport configuration", tag)
		}
		if live {
			if err := checkOutboundEndpoint(definition.config); err != nil {
				return nil, fmt.Errorf("outbound %q: %w", tag, err)
			}
			changed = append(changed, definition)
		}
		handler, err := create(definition.config)
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", tag, err)
		}
		if definition.live {
			handler = &outboundGeneration{Handler: handler, owner: m}
		}
		created = append(created, handler)
		if live {
			if err := handler.Start(); err != nil {
				return nil, fmt.Errorf("start outbound %q: %w", tag, err)
			}
		}
		next = append(next, customOutbound{definition.key, handler})
	}

	var retiring []*outboundGeneration
	removed := make(map[string]struct{})
	for _, entries := range old {
		for _, handler := range entries {
			generation, ok := handler.(*outboundGeneration)
			if !ok {
				return nil, fmt.Errorf("outbound %q requires a restart to replace or remove it", handler.Tag())
			}
			retiring = append(retiring, generation)
			if tag := handler.Tag(); tag != "" {
				if _, keep := tags[tag]; !keep {
					removed[tag] = struct{}{}
				}
			}
		}
	}
	if len(removed) > 0 && checkRemoved != nil {
		if err := checkRemoved(removed); err != nil {
			return nil, err
		}
	}
	if live {
		if err := m.checkOutboundDialers(definitions, changed, tags, removed); err != nil {
			return nil, err
		}
	}
	return func(apply bool) {
		defer m.mu.Unlock()
		if apply {
			m.publish(next)
			for _, handler := range retiring {
				handler.retire()
			}
		} else {
			for _, handler := range created {
				_ = handler.Close()
			}
		}
	}, nil
}

func (m *outboundManager) checkOutboundDialers(definitions, changed []outboundDefinition, tags, removed map[string]struct{}) error {
	dialers := make(map[string]string)
	for _, definition := range definitions {
		if _, gone := removed[definition.dialer]; gone {
			return fmt.Errorf("outbound %q still uses %q as its dialerProxy", definition.config.Tag, definition.dialer)
		}
		if tag := definition.config.Tag; tag != "" && definition.dialer != "" {
			dialers[tag] = definition.dialer
		}
	}
	for _, definition := range changed {
		target := definition.dialer
		if target == "" {
			continue
		}
		if _, ok := tags[target]; !ok && m.dynamic.GetHandler(target) == nil {
			return fmt.Errorf("outbound %q references missing dialerProxy %q", definition.config.Tag, target)
		}
		seen := make(map[string]struct{})
		for tag := target; tag != ""; tag = dialers[tag] {
			if _, ok := seen[tag]; ok {
				return fmt.Errorf("outbound %q has a dialerProxy cycle", definition.config.Tag)
			}
			seen[tag] = struct{}{}
		}
	}
	return nil
}

// PrepareOutbounds builds and starts the candidate handlers before publishing
// any of them. The caller finishes each prepared core exactly once.
func (c *Xray) PrepareOutbounds(config *conf.XrayConfig) (func(bool), error) {
	definitions, err := readOutboundDefinitions(config)
	if err != nil {
		return nil, err
	}
	manager, ok := c.Server.GetFeature(outbound.ManagerType()).(*outboundManager)
	if !ok {
		return nil, fmt.Errorf("live outbound manager is unavailable")
	}
	return manager.prepare(definitions, outboundFactory(c.Server), true, func(removed map[string]struct{}) error {
		router := c.Server.GetFeature(routing.RouterType()).(routing.Router)
		for _, rule := range router.ListRule() {
			if _, gone := removed[rule.GetOutboundTag()]; gone {
				return fmt.Errorf("outbound %q is still referenced by the running routes", rule.GetOutboundTag())
			}
		}
		return nil
	})
}

// CheckOutbounds preflights edits bundled with a main or route config reload.
// That reload owns route validation, so it can remove an outbound and its
// former route in the same edit.
func (c *Xray) CheckOutbounds(config *conf.XrayConfig) error {
	definitions, err := readOutboundDefinitions(config)
	if err != nil {
		return err
	}
	manager, ok := c.Server.GetFeature(outbound.ManagerType()).(*outboundManager)
	if !ok {
		manager, err = newOutboundManager(context.Background())
		if err != nil {
			return err
		}
	}
	finish, err := manager.prepare(definitions, outboundFactory(c.Server), true, nil)
	if err != nil {
		return err
	}
	finish(false)
	return nil
}
