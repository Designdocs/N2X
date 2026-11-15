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
