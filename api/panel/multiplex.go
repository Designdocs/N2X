package panel

import "encoding/json"

// MultiplexSettings is the panel's per-node multiplex switch. X-Board hands
// the same object to the subscription generator, which turns it into a
// sing-mux `smux` block on every client; the node must therefore accept
// sing-mux exactly when this is enabled, or those clients cannot connect.
type MultiplexSettings struct {
	Enabled bool
	// Padding makes clients pad their mux frames; a padded server rejects
	// unpadded sessions, so it mirrors the panel instead of a local choice.
	Padding bool
}

// UnmarshalJSON never fails: a malformed multiplex object must not take the
// whole node offline, so anything unreadable decodes as "disabled".
func (m *MultiplexSettings) UnmarshalJSON(data []byte) error {
	*m = MultiplexSettings{}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	m.Enabled = panelTruthy(raw["enabled"])
	m.Padding = panelTruthy(raw["padding"])
	return nil
}

// MultiplexEnabled reports whether the panel switched multiplex on.
func (c *CommonNode) MultiplexEnabled() bool {
	return c != nil && c.Multiplex != nil && c.Multiplex.Enabled
}

func panelTruthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v == "1" || v == "true"
	default:
		return false
	}
}
