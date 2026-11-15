package panel

// Runtime status is scoped to this backend instance. It carries panel user IDs,
// never UUIDs, tokens, source addresses or destination traffic details.
type DynamicSpeedPenalty struct {
	ID           string  `json:"id"`
	UserID       int     `json:"user_id"`
	StartedAt    int64   `json:"started_at"`
	ExpiresAt    int64   `json:"expires_at"`
	LimitMbps    int     `json:"limit_mbps"`
	MeasuredMbps float64 `json:"measured_mbps"`
	Revision     int64   `json:"revision"`
}

type DynamicSpeedEvent struct {
	ID        string `json:"id"`
	PenaltyID string `json:"penalty_id"`
	UserID    int    `json:"user_id"`
	Kind      string `json:"kind"`
	At        int64  `json:"at"`
}

type DynamicSpeedStatus struct {
	Version          int                   `json:"version"`
	Enabled          bool                  `json:"enabled"`
	AppliedRevision  int64                 `json:"applied_revision"`
	SampleSeconds    int                   `json:"sample_seconds"`
	LimitedUsers     int                   `json:"limited_users"`
	ObservingUsers   int                   `json:"observing_users"`
	Penalties        []DynamicSpeedPenalty `json:"penalties"`
	Events           []DynamicSpeedEvent   `json:"events"`
	ReleasedCommands []string              `json:"released_commands"`
	StateError       string                `json:"state_error,omitempty"`
	PolicyError      string                `json:"policy_error,omitempty"`
}
