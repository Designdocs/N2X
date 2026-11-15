package panel

import (
	"net/http"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestNodeDynamicPolicyUsesDefaultsUntilPanelOverridesThem(t *testing.T) {
	body := `{"server_port":443,"network":"tcp","dynamic_speed_limit":{"enabled":true,"over_threshold_percent":90}}`
	c := noopPanelClient(t, func(r *http.Request) (*http.Response, error) {
		return textResponse(r, http.StatusOK, body), nil
	})
	node, err := c.GetNodeInfo()
	if err != nil || node == nil || node.DynamicSpeedLimit == nil {
		t.Fatalf("partial policy: %v %+v", err, node)
	}
	want := conf.DefaultNodeDynamicSpeedPolicy()
	want.Enabled, want.OverThresholdPercent = true, 90
	if *node.DynamicSpeedLimit != want {
		t.Fatalf("panel/default merge: %+v", node.DynamicSpeedLimit)
	}
	body = `{"server_port":443,"network":"tcp","dynamic_speed_limit":{"enabled":false,"threshold_mbps":80,"sustain_seconds":240,"over_threshold_percent":95,"limit_mbps":8,"penalty_seconds":3600,"exemptions_revision":2}}`
	node, err = c.GetNodeInfo()
	if err != nil || node == nil || node.DynamicSpeedLimit.Enabled || node.DynamicSpeedLimit.ThresholdMbps != 80 || node.DynamicSpeedLimit.PenaltySeconds != 3600 || node.DynamicSpeedLimit.ExemptionsRevision != 2 {
		t.Fatalf("explicit panel override: %v %+v", err, node)
	}
	body = `{"server_port":443,"network":"tcp","dynamic_speed_limit":{"over_threshold_percent":0}}`
	for range 2 {
		if _, err := c.GetNodeInfo(); err == nil {
			t.Fatal("invalid policy was accepted or cached as unchanged")
		}
	}
}
