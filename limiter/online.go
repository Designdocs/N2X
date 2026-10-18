package limiter

import (
	"net/netip"
	"sync"

	"github.com/Designdocs/N2X/api/panel"
)

type onlineUser struct {
	uid int
	ips map[string]int
}

// TrackConnection binds an admitted connection to its authenticated identity.
// The returned close callback owns this registration, even after policy updates.
func (l *Limiter) TrackConnection(tagUUID, ip string) func() {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return func() {}
	}
	ip = addr.Unmap().String()
	l.onlineMu.Lock()
	info, ok := l.UserLimitInfo.Load(tagUUID)
	if !ok {
		l.onlineMu.Unlock()
		return func() {}
	}
	uid := info.(*UserLimitInfo).UID
	if l.onlineUsers == nil {
		l.onlineUsers = make(map[string]*onlineUser)
	}
	user := l.onlineUsers[tagUUID]
	if user == nil || user.uid != uid {
		user = &onlineUser{uid: uid, ips: make(map[string]int)}
		l.onlineUsers[tagUUID] = user
	}
	user.ips[ip]++
	l.onlineMu.Unlock()

	return sync.OnceFunc(func() {
		l.onlineMu.Lock()
		defer l.onlineMu.Unlock()
		if l.onlineUsers[tagUUID] != user {
			return
		}
		user.ips[ip]--
		if user.ips[ip] == 0 {
			delete(user.ips, ip)
		}
		if len(user.ips) == 0 {
			delete(l.onlineUsers, tagUUID)
		}
	})
}

func (l *Limiter) onlineDevicesLocked() []panel.OnlineUser {
	var devices []panel.OnlineUser
	seen := make(map[panel.OnlineUser]struct{})
	for _, user := range l.onlineUsers {
		for ip := range user.ips {
			device := panel.OnlineUser{UID: user.uid, IP: ip}
			if _, exists := seen[device]; !exists {
				seen[device] = struct{}{}
				devices = append(devices, device)
			}
		}
	}
	return devices
}
