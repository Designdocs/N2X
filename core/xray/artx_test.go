package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildArtXUsesAnyTLSUnderlayWithoutRewritingNodeType(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Type: "artx",
		ArtX: &panel.ArtXNode{
			Underlay:       "anytls",
			Profile:        "balanced",
			ProfileVersion: 1,
			PaddingScheme:  []string{"stop=8", "0=30-30"},
		},
	}
	inbound := &coreConf.InboundDetourConfig{}

	if err := buildArtX(nodeInfo, inbound); err != nil {
		t.Fatalf("buildArtX returned error: %v", err)
	}
	if nodeInfo.Type != "artx" {
		t.Fatalf("expected node type to stay artx, got %q", nodeInfo.Type)
	}
	if inbound.Protocol != "anytls" {
		t.Fatalf("expected Xray underlay protocol anytls, got %q", inbound.Protocol)
	}
	if inbound.StreamSetting == nil || inbound.StreamSetting.Network == nil {
		t.Fatal("expected ArtX to configure a TCP stream")
	}
	if string(*inbound.StreamSetting.Network) != "tcp" {
		t.Fatalf("expected TCP stream, got %q", string(*inbound.StreamSetting.Network))
	}

	var settings struct {
		PaddingScheme []string `json:"paddingScheme"`
	}
	if inbound.Settings == nil {
		t.Fatal("expected ArtX to configure underlay settings")
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal underlay settings failed: %v", err)
	}
	if strings.Join(settings.PaddingScheme, "\n") != "stop=8\n0=30-30" {
		t.Fatalf("unexpected padding scheme: %+v", settings.PaddingScheme)
	}
}

func TestBuildArtXRejectsUnsupportedUnderlay(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Type: "artx",
		ArtX: &panel.ArtXNode{
			Underlay: "custom",
		},
	}

	if err := buildArtX(nodeInfo, &coreConf.InboundDetourConfig{}); err == nil {
		t.Fatal("expected unsupported ArtX underlay to fail")
	}
}
