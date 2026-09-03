package node

import (
	"errors"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
)

func artXWireNode(flowControl string) *panel.NodeInfo {
	return &panel.NodeInfo{
		Id:   7,
		Type: "artx",
		ArtX: &panel.ArtXNode{
			CommonNode: panel.CommonNode{
				Host:       "tw.example.com",
				ServerPort: 443,
			},
			Underlay:    "artx-wire",
			WireVersion: 2,
			FlowControl: flowControl,
		},
	}
}

func TestArtXFlowControlOnlyChangeAcceptsATierSwap(t *testing.T) {
	old := artXWireNode(panel.ArtXFlowControlAuto)
	updated := artXWireNode(panel.ArtXFlowControlHighLatency)
	if !artXFlowControlOnlyChange(old, updated) {
		t.Fatal("a pure tier swap should be eligible for an in-place retier")
	}
	if old.ArtX.FlowControl != panel.ArtXFlowControlAuto {
		t.Fatalf("the comparison rewrote its input: %q", old.ArtX.FlowControl)
	}
}

func TestArtXFlowControlOnlyChangeRejectsEverythingElse(t *testing.T) {
	cases := map[string]func(old, updated *panel.NodeInfo){
		"identical tiers": func(old, updated *panel.NodeInfo) {
			updated.ArtX.FlowControl = old.ArtX.FlowControl
		},
		"port moved too": func(_, updated *panel.NodeInfo) {
			updated.ArtX.ServerPort = 8443
		},
		"wire version moved too": func(_, updated *panel.NodeInfo) {
			updated.ArtX.WireVersion = 3
		},
		"rules moved too": func(_, updated *panel.NodeInfo) {
			updated.Rules = panel.Rules{Regexp: []string{"^ads\\."}}
		},
		"no longer artx wire": func(_, updated *panel.NodeInfo) {
			updated.ArtX.Underlay = "tcp"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			old := artXWireNode(panel.ArtXFlowControlAuto)
			updated := artXWireNode(panel.ArtXFlowControlHighLatency)
			mutate(old, updated)
			if artXFlowControlOnlyChange(old, updated) {
				t.Fatal("this change needs the full reload, not an in-place retier")
			}
		})
	}
}

func TestArtXFlowControlOnlyChangeRejectsNonArtXNodes(t *testing.T) {
	artX := artXWireNode(panel.ArtXFlowControlAuto)
	if artXFlowControlOnlyChange(nil, artX) || artXFlowControlOnlyChange(artX, nil) {
		t.Fatal("a missing node body is never eligible")
	}
	shadowsocks := &panel.NodeInfo{Type: "shadowsocks"}
	if artXFlowControlOnlyChange(shadowsocks, shadowsocks) {
		t.Fatal("a node without ArtX settings is never eligible")
	}
}

func retierController(server vCore.Core, node *panel.NodeInfo) *Controller {
	return &Controller{server: server, tag: "artx-canary", info: node, Options: &conf.Options{}}
}

func TestRetierArtXFlowControlAppliesTheNewTier(t *testing.T) {
	server := &artXFlowControlCore{}
	updated := artXWireNode(panel.ArtXFlowControlHighLatency)
	controller := retierController(server, artXWireNode(panel.ArtXFlowControlAuto))

	if !controller.retierArtXFlowControl(updated) {
		t.Fatal("the retier should have been reported as applied")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.tiers) != 1 || server.tiers[0] != panel.ArtXFlowControlHighLatency {
		t.Fatalf("tiers = %#v, want [%s]", server.tiers, panel.ArtXFlowControlHighLatency)
	}
}

func TestRetierArtXFlowControlFallsBackWhenTheCoreRefuses(t *testing.T) {
	server := &artXFlowControlCore{tierErr: errors.New("no such inbound")}
	controller := retierController(server, artXWireNode(panel.ArtXFlowControlAuto))

	if controller.retierArtXFlowControl(artXWireNode(panel.ArtXFlowControlHighLatency)) {
		t.Fatal("a core that refuses the retier must send the caller back to the full reload")
	}
}

func TestRetierArtXFlowControlSkipsNonWireNodes(t *testing.T) {
	server := &artXFlowControlCore{}
	anytls := artXWireNode(panel.ArtXFlowControlHighLatency)
	anytls.ArtX.Underlay = "anytls"

	if retierController(server, anytls).retierArtXFlowControl(anytls) {
		t.Fatal("a node that does not run native ArtX wire has no tier to retier")
	}
}
