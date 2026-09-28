package sing

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/counter"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/core"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

// UserDeleter is implemented by every sing-box inbound that supports live
// user removal.
type UserDeleter interface {
	DelUsers(names []string) error
}

// userInboundTag returns the inbound that owns the node's users. For
// ShadowTLS that is the internal Shadowsocks detour, not the public listener.
func userInboundTag(tag string, nodeType string) string {
	if nodeType == "shadowtls" {
		return detourTag(tag)
	}
	return tag
}

func (b *Sing) AddUsers(p *core.AddUsersParams) (added int, err error) {
	// Naive has no live user API and is rebuilt from its user set instead.
	if p.NodeInfo.Type == "naive" {
		if added, err = b.addNaiveUsers(p.Tag, p.Users); err != nil {
			return 0, err
		}
		b.rememberUsers(p.Tag, p.Users)
		return added, nil
	}

	in, found := b.box.Inbound().Get(userInboundTag(p.Tag, p.NodeInfo.Type))
	if !found {
		return 0, fmt.Errorf("the inbound %s is not found", p.Tag)
	}

	switch p.NodeInfo.Type {
	case "vless":
		us := make([]option.VLESSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VLESSUser{
				Name: p.Users[i].Uuid,
				Flow: p.VAllss.Flow,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vless.Inbound).AddUsers(us)
	case "vmess":
		us := make([]option.VMessUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VMessUser{
				Name: p.Users[i].Uuid,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vmess.Inbound).AddUsers(us)
	case "shadowsocks":
		err = in.(*shadowsocks.MultiInbound).AddUsers(
			buildShadowsocksUsers(p.Users, p.Shadowsocks.Cipher))
	case "shadowtls":
		err = in.(*shadowsocks.MultiInbound).AddUsers(
			buildShadowsocksUsers(p.Users, p.ShadowTLS.Cipher))
	case "trojan":
		us := make([]option.TrojanUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.TrojanUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*trojan.Inbound).AddUsers(us)
	case "anytls":
		us := make([]option.AnyTLSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.AnyTLSUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*anytls.Inbound).AddUsers(us)
	case "tuic":
		us := make([]option.TUICUser, len(p.Users))
		ids := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.TUICUser{
				Name:     p.Users[i].Uuid,
				UUID:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			ids[i] = p.Users[i].Id
		}
		err = in.(*tuic.Inbound).AddUsers(us, ids)
	case "hysteria":
		us := make([]option.HysteriaUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.HysteriaUser{
				Name:       p.Users[i].Uuid,
				AuthString: p.Users[i].Uuid,
			}
		}
		err = in.(*hysteria.Inbound).AddUsers(us)
	case "hysteria2":
		us := make([]option.Hysteria2User, len(p.Users))
		ids := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.Hysteria2User{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			ids[i] = p.Users[i].Id
		}
		err = in.(*hysteria2.Inbound).AddUsers(us, ids)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	if err != nil {
		return 0, err
	}
	b.rememberUsers(p.Tag, p.Users)
	return len(p.Users), nil
}

// buildShadowsocksUsers derives per-user Shadowsocks credentials. The 2022
// ciphers take a fixed-length pre-shared key rather than a passphrase, so the
// UUID is truncated to the cipher's key size and base64 encoded.
func buildShadowsocksUsers(users []panel.UserInfo, cipher string) []option.ShadowsocksUser {
	us := make([]option.ShadowsocksUser, len(users))
	for i := range users {
		password := users[i].Uuid
		if strings.Contains(cipher, "2022") {
			keyLength := shadowsocksKeyLength(cipher)
			if len(password) >= keyLength {
				password = base64.StdEncoding.EncodeToString([]byte(password[:keyLength]))
			} else {
				password = base64.StdEncoding.EncodeToString([]byte(password))
			}
		}
		us[i] = option.ShadowsocksUser{
			Name:     users[i].Uuid,
			Password: password,
		}
	}
	return us
}

// rememberUsers records the panel user id behind each per-node identity so
// traffic can be reported against it. Keys are scoped by node tag: the same
// user may exist on several nodes and removing them from one must not blank
// out the mapping used by the others.
func (b *Sing) rememberUsers(tag string, users []panel.UserInfo) {
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()
	for i := range users {
		b.users.uidMap[format.UserTag(tag, users[i].Uuid)] = users[i].Id
	}
}

func (b *Sing) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	if info.Type == "naive" {
		if err := b.delNaiveUsers(tag, users); err != nil {
			return err
		}
		b.forgetUsers(tag, users)
		return nil
	}

	i, found := b.box.Inbound().Get(userInboundTag(tag, info.Type))
	if !found {
		return fmt.Errorf("the inbound %s is not found", tag)
	}
	var del UserDeleter
	switch info.Type {
	case "vmess":
		del = i.(*vmess.Inbound)
	case "vless":
		del = i.(*vless.Inbound)
	case "shadowsocks", "shadowtls":
		del = i.(*shadowsocks.MultiInbound)
	case "trojan":
		del = i.(*trojan.Inbound)
	case "anytls":
		del = i.(*anytls.Inbound)
	case "tuic":
		del = i.(*tuic.Inbound)
	case "hysteria":
		del = i.(*hysteria.Inbound)
	case "hysteria2":
		del = i.(*hysteria2.Inbound)
	default:
		return fmt.Errorf("unsupported node type: %s", info.Type)
	}

	names := make([]string, len(users))
	for i := range users {
		names[i] = users[i].Uuid
	}
	if err := del.DelUsers(names); err != nil {
		return err
	}
	b.forgetUsers(tag, users)
	return nil
}

// forgetUsers drops the users' accounting state for a node.
func (b *Sing) forgetUsers(tag string, users []panel.UserInfo) {
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()
	c, hasCounter := b.hookServer.counter.Load(tag)
	for i := range users {
		if hasCounter {
			c.(*counter.TrafficCounter).Delete(users[i].Uuid)
		}
		delete(b.users.uidMap, format.UserTag(tag, users[i].Uuid))
	}
}

func (b *Sing) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	v, ok := b.hookServer.counter.Load(tag)
	if !ok {
		return nil, nil
	}
	c := v.(*counter.TrafficCounter)
	minTraffic := b.reportMinTraffic(tag)

	trafficSlice := make([]panel.UserTraffic, 0)
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	c.Counters.Range(func(key, value interface{}) bool {
		uuid := key.(string)
		traffic := value.(*counter.TrafficStorage)
		up := traffic.UpCounter.Load()
		down := traffic.DownCounter.Load()
		if up+down <= minTraffic {
			return true
		}
		if reset {
			traffic.UpCounter.Store(0)
			traffic.DownCounter.Store(0)
		}
		uid, known := b.users.uidMap[format.UserTag(tag, uuid)]
		if !known || uid == 0 {
			// Traffic from a user this node no longer serves: drop the
			// counter rather than reporting it against an unknown id.
			c.Delete(uuid)
			return true
		}
		trafficSlice = append(trafficSlice, panel.UserTraffic{
			UID:      uid,
			Upload:   up,
			Download: down,
		})
		return true
	})
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	return trafficSlice, nil
}
