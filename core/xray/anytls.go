package xray

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
)

type anyTLSUnderlayConfig struct {
	PaddingScheme []string
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	if nodeInfo.AnyTls == nil {
		return errors.New("missing anytls node settings")
	}
	return buildAnyTLSUnderlayInbound(inbound, anyTLSUnderlayConfig{
		PaddingScheme: nodeInfo.AnyTls.PaddingScheme,
	})
}

func buildAnyTLSUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	return buildAnyTLSUnderlayUsers(tag, userInfo)
}

func buildAnyTLSUnderlayInbound(inbound *coreConf.InboundDetourConfig, config anyTLSUnderlayConfig) error {
	inbound.Protocol = "anytls"
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: config.PaddingScheme,
	}
	rawSettings, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&rawSettings)
	return nil
}

func buildAnyTLSUnderlayUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildAnyTLSUnderlayUser(tag, &userInfo[i])
	}
	return users
}

func buildAnyTLSUnderlayUser(tag string, userInfo *panel.UserInfo) *protocol.User {
	account := &anytls.Account{
		Password: userInfo.Uuid,
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(account),
	}
}
