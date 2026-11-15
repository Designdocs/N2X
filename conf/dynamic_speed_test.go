package conf

import (
	"encoding/json"
	"testing"
)

func TestDynamicSpeedPolicyRatioCompatibility(t *testing.T) {
	var policy NodeDynamicSpeedPolicy
	if err := json.Unmarshal([]byte(`{"version":1,"revision":7,"enabled":true,"threshold_mbps":50,"sustain_seconds":180,"limit_mbps":5,"penalty_seconds":1800}`), &policy); err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(); err != nil || policy.EffectiveOverThresholdPercent() != 85 {
		t.Fatalf("legacy policy did not acquire the default ratio: %+v %v", policy, err)
	}
	policy.Version = DynamicSpeedPolicyVersion
	policy.OverThresholdPercent = 0
	if err := policy.Validate(); err == nil {
		t.Fatal("v2 accepted a missing percentage")
	}
	for _, percent := range []int{1, 85, 100} {
		policy.OverThresholdPercent = percent
		if err := policy.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	policy.OverThresholdPercent = 101
	if err := policy.Validate(); err == nil {
		t.Fatal("invalid percentage was accepted")
	}
}

func TestDynamicSpeedPanelDefaultsAndExplicitOverrides(t *testing.T) {
	for _, body := range []string{`{}`, `{"threshold_mbps":null,"sustain_seconds":null,"over_threshold_percent":null,"limit_mbps":null,"penalty_seconds":null}`} {
		var policy NodeDynamicSpeedPolicy
		if err := json.Unmarshal([]byte(body), &policy); err != nil {
			t.Fatal(err)
		}
		if policy != DefaultNodeDynamicSpeedPolicy() || policy.Validate() != nil {
			t.Fatalf("omitted fields did not acquire disabled defaults: %+v", policy)
		}
	}
	var policy NodeDynamicSpeedPolicy
	if err := json.Unmarshal([]byte(`{"enabled":true,"over_threshold_percent":90}`), &policy); err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled || policy.OverThresholdPercent != 90 || policy.ThresholdMbps != 50 || policy.PenaltySeconds != 1800 {
		t.Fatalf("partial panel policy did not take precedence: %+v", policy)
	}
	if err := json.Unmarshal([]byte(`{"version":2,"revision":17,"exemptions_revision":3,"enabled":false,"threshold_mbps":80,"sustain_seconds":240,"over_threshold_percent":95,"limit_mbps":8,"penalty_seconds":28800}`), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Enabled || policy.Revision != 17 || policy.ExemptionsRevision != 3 || policy.ThresholdMbps != 80 || policy.SustainSeconds != 240 || policy.OverThresholdPercent != 95 || policy.LimitMbps != 8 || policy.PenaltySeconds != 28800 || policy.Validate() != nil {
		t.Fatalf("explicit panel policy lost values: %+v", policy)
	}
	for _, body := range []string{`{"threshold_mbps":0}`, `{"over_threshold_percent":0}`, `{"exemptions_revision":-1}`, `{"sustain_seconds":31}`} {
		if err := json.Unmarshal([]byte(body), &policy); err != nil {
			t.Fatal(err)
		}
		if err := policy.Validate(); err == nil {
			t.Fatalf("explicit invalid panel field was replaced by a default: %s", body)
		}
	}
}
