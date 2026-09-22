package node

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
)

func deviceLimitNode(tolerance int, ignored ...string) *panel.NodeInfo {
	return &panel.NodeInfo{
		Id:                    7,
		Type:                  "trojan",
		DeviceLimitTolerance:  tolerance,
		DeviceLimitIgnoredIPs: ignored,
		Trojan: &panel.TrojanNode{
			CommonNode: panel.CommonNode{Host: "uk.example.com", ServerPort: 443},
		},
	}
}

func TestDeviceLimitOnlyChangeAcceptsPolicyMoves(t *testing.T) {
	cases := map[string][2]*panel.NodeInfo{
		"relay exit re-resolved": {deviceLimitNode(1, "56.69.64.164/32"), deviceLimitNode(1, "56.69.64.165/32")},
		"list emptied":           {deviceLimitNode(1, "56.69.64.164/32"), deviceLimitNode(1)},
		"list introduced":        {deviceLimitNode(1), deviceLimitNode(1, "10.0.0.0/8")},
		"tolerance moved":        {deviceLimitNode(1), deviceLimitNode(3)},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			old, updated := pair[0], pair[1]
			if !deviceLimitOnlyChange(old, updated) {
				t.Fatal("a pure device-limit policy change should be applied in place")
			}
			if old.DeviceLimitTolerance != 1 || len(old.DeviceLimitIgnoredIPs) != len(pair[0].DeviceLimitIgnoredIPs) {
				t.Fatal("the comparison rewrote its input")
			}
		})
	}
}

func TestDeviceLimitOnlyChangeRejectsEverythingElse(t *testing.T) {
	cases := map[string]func(old, updated *panel.NodeInfo){
		"identical policy": func(old, updated *panel.NodeInfo) {
			updated.DeviceLimitIgnoredIPs = old.DeviceLimitIgnoredIPs
		},
		"port moved too": func(_, updated *panel.NodeInfo) {
			updated.Trojan.ServerPort = 8443
		},
		"rules moved too": func(_, updated *panel.NodeInfo) {
			updated.Rules = panel.Rules{Regexp: []string{"^ads\\."}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			old := deviceLimitNode(1, "56.69.64.164/32")
			updated := deviceLimitNode(1, "56.69.64.165/32")
			mutate(old, updated)
			if deviceLimitOnlyChange(old, updated) {
				t.Fatal("this change needs the full reload")
			}
		})
	}
	if deviceLimitOnlyChange(nil, deviceLimitNode(1)) || deviceLimitOnlyChange(deviceLimitNode(1), nil) {
		t.Fatal("a missing node body is never eligible")
	}
}
