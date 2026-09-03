package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/artx"
)

func buildArtXWireInbound(option *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	if nodeInfo.ArtX.WireVersion != artXWireVersion {
		return fmt.Errorf("unsupported artx wire version: %d", nodeInfo.ArtX.WireVersion)
	}
	if nodeInfo.ArtX.ProfileVersion != artXWireDefaultProfileVersion && nodeInfo.ArtX.ProfileVersion != 3 {
		return fmt.Errorf("unsupported artx profile version: %d", nodeInfo.ArtX.ProfileVersion)
	}
	maxWindowScale, flowControlAuto, err := artXFlowControlPolicy(nodeInfo.ArtX)
	if err != nil {
		return err
	}
	tlsSettings, err := buildInboundTLSConfig(option, nodeInfo)
	if err != nil {
		return err
	}
	if tlsSettings == nil {
		return errors.New("artx wire requires TLS certificate settings")
	}
	fallback, err := resolveArtXFallback(nodeInfo.ArtX.Fallback, nodeInfo.ArtX.Profile)
	if err != nil {
		return fmt.Errorf("resolve artx fallback: %w", err)
	}

	inbound.Protocol = "artx"
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	settings := &coreConf.ArtXServerConfig{
		TLSSettings:     tlsSettings,
		WireVersion:     uint32(nodeInfo.ArtX.WireVersion),
		ProfileVersion:  uint32(nodeInfo.ArtX.ProfileVersion),
		UDPEnabled:      nodeInfo.ArtX.UDP,
		MaxWindowScale:  maxWindowScale,
		FlowControlAuto: flowControlAuto,
		Fallback:        fallback,
	}
	rawSettings, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal artx wire settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&rawSettings)
	logArtXWireBuildObservation(newArtXWireBuildObservation(nodeInfo.ArtX, fallback != nil))
	return nil
}

type artXWireBuildObservation struct {
	Protocol          string `json:"protocol"`
	Underlay          string `json:"underlay"`
	ProfileVersion    int    `json:"profile_version"`
	FlowControl       string `json:"flow_control"`
	MaxWindowScale    int    `json:"max_window_scale"`
	FlowControlAuto   bool   `json:"flow_control_auto"`
	FallbackMode      string `json:"fallback_mode"`
	FallbackAvailable bool   `json:"fallback_available"`
}

func newArtXWireBuildObservation(node *panel.ArtXNode, fallbackAvailable bool) artXWireBuildObservation {
	maxWindowScale, flowControlAuto, _ := artXFlowControlPolicy(node)
	fallbackMode := "disabled"
	if node.Fallback.Enabled {
		fallbackMode = "https-origin"
		if strings.TrimSpace(node.Fallback.Origin) == artXDecoySelector {
			fallbackMode = "installed-decoy"
		}
	}

	return artXWireBuildObservation{
		Protocol:          "artx",
		Underlay:          artXUnderlayWire,
		ProfileVersion:    node.ProfileVersion,
		FlowControl:       canonicalArtXFlowControl(node.FlowControl),
		MaxWindowScale:    int(maxWindowScale),
		FlowControlAuto:   flowControlAuto,
		FallbackMode:      fallbackMode,
		FallbackAvailable: fallbackAvailable,
	}
}

func logArtXWireBuildObservation(observation artXWireBuildObservation) {
	log.WithFields(log.Fields{
		"protocol":           observation.Protocol,
		"underlay":           observation.Underlay,
		"profile_version":    observation.ProfileVersion,
		"flow_control":       observation.FlowControl,
		"max_window_scale":   observation.MaxWindowScale,
		"flow_control_auto":  observation.FlowControlAuto,
		"fallback_mode":      observation.FallbackMode,
		"fallback_available": observation.FallbackAvailable,
	}).Info("artx wire inbound observation")
}

// artXFlowControlPolicy maps the panel's flow-control name onto the two
// settings the core takes: the window scale and whether that scale is a fixed
// setting or an upper bound the core sizes down from per connection.
//
// The auto policy needs both a rate lookup and host pressure samples to do
// anything useful; without them the core falls back to its own defaults, so
// the mapping stays valid even when the agent has not published either yet.
func artXFlowControlPolicy(node *panel.ArtXNode) (maxWindowScale uint32, auto bool, err error) {
	switch canonicalArtXFlowControl(node.FlowControl) {
	case panel.ArtXFlowControlLegacy:
		return 0, false, nil
	case panel.ArtXFlowControlMediumLatency:
		return panel.ArtXMediumLatencyWindowScale, false, nil
	case panel.ArtXFlowControlHighLatency:
		return panel.ArtXHighLatencyWindowScale, false, nil
	case panel.ArtXFlowControlAuto:
		return panel.ArtXAutoWindowScale, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported artx flow control: %s", node.FlowControl)
	}
}

func canonicalArtXFlowControl(flowControl string) string {
	flowControl = strings.TrimSpace(flowControl)
	if flowControl == "" {
		return panel.ArtXFlowControlLegacy
	}
	return flowControl
}

func artXWireHandlesTLS(nodeInfo *panel.NodeInfo) bool {
	return nodeInfo != nil && nodeInfo.ArtX != nil && normalizeArtXUnderlay(nodeInfo.ArtX.Underlay) == artXUnderlayWire
}

func buildArtXWireUsers(tag string, userInfo []panel.UserInfo) []*protocol.User {
	users := make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo[i].Uuid),
			Account: serial.ToTypedMessage(&artx.Account{Psk: userInfo[i].Uuid}),
		}
	}
	return users
}
