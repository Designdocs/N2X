package xray

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/artx"
)

func buildArtXWireInbound(option *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	if nodeInfo.ArtX.WireVersion != artXWireVersion {
		return fmt.Errorf("unsupported artx wire version: %d", nodeInfo.ArtX.WireVersion)
	}
	if nodeInfo.ArtX.ProfileVersion != artXWireProfileVersion {
		return fmt.Errorf("unsupported artx profile version: %d", nodeInfo.ArtX.ProfileVersion)
	}
	tlsSettings, err := buildInboundTLSConfig(option, nodeInfo)
	if err != nil {
		return err
	}
	if tlsSettings == nil {
		return errors.New("artx wire requires TLS certificate settings")
	}

	inbound.Protocol = "artx"
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	settings := &coreConf.ArtXServerConfig{
		TLSSettings:    tlsSettings,
		WireVersion:    uint32(nodeInfo.ArtX.WireVersion),
		ProfileVersion: uint32(nodeInfo.ArtX.ProfileVersion),
	}
	rawSettings, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal artx wire settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&rawSettings)
	return nil
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
