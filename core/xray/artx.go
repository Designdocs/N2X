package xray

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/xtls/xray-core/common/protocol"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const artXUnderlayAnyTLS = "anytls"

func buildArtX(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	if nodeInfo.ArtX == nil {
		return errors.New("missing artx node settings")
	}

	switch normalizeArtXUnderlay(nodeInfo.ArtX.Underlay) {
	case artXUnderlayAnyTLS:
		return buildAnyTLSUnderlayInbound(inbound, anyTLSUnderlayConfig{
			PaddingScheme: nodeInfo.ArtX.PaddingScheme,
		})
	default:
		return fmt.Errorf("unsupported artx underlay: %s", nodeInfo.ArtX.Underlay)
	}
}

func normalizeArtXUnderlay(underlay string) string {
	normalized := strings.ToLower(strings.TrimSpace(underlay))
	if normalized == "" {
		return artXUnderlayAnyTLS
	}
	return normalized
}

func buildArtXUsers(tag string, userInfo []panel.UserInfo) []*protocol.User {
	return buildAnyTLSUnderlayUsers(tag, userInfo)
}
