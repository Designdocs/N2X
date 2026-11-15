package conf

import "fmt"

// NodeDynamicSpeedPolicy is a panel-owned policy. A nil policy means the
// panel has not taken ownership; an explicit disabled policy overrides local
// legacy dynamic limits. Rates are decimal Mbps and durations are seconds.
type NodeDynamicSpeedPolicy struct {
	Version        int   `json:"version"`
	Revision       int64 `json:"revision"`
	Enabled        bool  `json:"enabled"`
	ThresholdMbps  int   `json:"threshold_mbps"`
	SustainSeconds int   `json:"sustain_seconds"`
	LimitMbps      int   `json:"limit_mbps"`
	PenaltySeconds int   `json:"penalty_seconds"`
}

const DynamicSpeedSampleSeconds = 5

func (p *NodeDynamicSpeedPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if p.Version != 1 || p.Revision < 0 {
		return fmt.Errorf("unsupported dynamic speed policy version or revision")
	}
	if p.ThresholdMbps < 1 || p.ThresholdMbps > 100000 || p.LimitMbps < 1 || p.LimitMbps >= p.ThresholdMbps {
		return fmt.Errorf("dynamic speed rates must satisfy 1 <= limit < threshold <= 100000 Mbps")
	}
	if p.SustainSeconds < 30 || p.SustainSeconds > 3600 || p.SustainSeconds%DynamicSpeedSampleSeconds != 0 {
		return fmt.Errorf("dynamic speed duration must be 30..3600 seconds in 5-second steps")
	}
	if p.PenaltySeconds < 60 || p.PenaltySeconds > 86400 {
		return fmt.Errorf("dynamic speed penalty must be 60..86400 seconds")
	}
	return nil
}

// A release names one particular penalty, so delayed/repeated commands can
// never release a newer penalty or a different backend instance's penalty.
type DynamicSpeedCommand struct {
	ID        string `json:"id"`
	PenaltyID string `json:"penalty_id"`
	UserID    int    `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}
