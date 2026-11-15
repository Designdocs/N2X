package limiter

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/cdn"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/common/rate"
	"github.com/Designdocs/N2X/conf"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	DomainRules   []*regexp.Regexp
	ProtocolRules []string
	SpeedLimit    int
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Previous period, keyed by the same TagUUID and IP
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *rate.Controller (stable across rate edits)
	userMu        sync.RWMutex
	dynamic       dynamicState
	AliveList     map[int]int // Key: Uid, value: alive_ip
	aliveMu       sync.RWMutex
	onlineMu      sync.Mutex
	onlineUsers   map[string]*onlineUser

	// KickedIPs holds panel-issued device kicks: uid → ip → unix expiry.
	// A kicked IP is rejected outright until its entry expires, so the
	// freed device slot cannot be re-occupied by an auto-reconnect.
	KickedIPs map[int]map[string]int64
	kickedMu  sync.RWMutex

	// deviceTolerance is panel-configured headroom over DeviceLimit so a
	// device hopping nodes/networks is not rejected by its own stale entry.
	deviceTolerance atomic.Int32

	// ignoredPrefixes is the panel's operator ignore list (relay exits,
	// probes). Like CDN ranges these addresses are reported but never
	// occupy a device slot. Replaced wholesale on every config pull.
	ignoredPrefixes atomic.Pointer[[]netip.Prefix]
	cdnPolicy       cdn.Policy
}

type UserLimitInfo struct {
	UID                int
	SpeedLimit         int
	DeviceLimit        int
	DynamicSpeedLimit  int
	ExpireTime         int64
	OverLimit          bool
	DynamicSpeedExempt bool
}

func AddLimiter(tag string, l *conf.LimitConfig, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		SpeedLimit:    l.SpeedLimit,
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     cloneAliveList(aliveList),
		OldUserOnline: new(sync.Map),
		KickedIPs:     make(map[int]map[string]int64),
	}
	info.deviceTolerance.Store(1)
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		userLimit.DynamicSpeedExempt = users[i].DynamicSpeedExempt
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	l.onlineMu.Lock()
	defer l.onlineMu.Unlock()
	l.userMu.Lock()
	defer l.userMu.Unlock()
	retained := make(map[string]int, len(added))
	retainedIDs := make(map[int]bool, len(added))
	movedPenalties := make(map[int]activePenalty)
	for _, user := range added {
		retained[format.UserTag(tag, user.Uuid)] = user.Id
		retainedIDs[user.Id] = true
	}
	for i := range deleted {
		tagUUID := format.UserTag(tag, deleted[i].Uuid)
		if uid, remains := retained[tagUUID]; remains && uid == deleted[i].Id {
			continue
		}
		if uid, remains := retained[tagUUID]; !remains || uid != deleted[i].Id {
			delete(l.onlineUsers, tagUUID)
			l.OldUserOnline.Delete(tagUUID)
		}
		if p, ok := l.dynamic.penalties[tagUUID]; ok && retainedIDs[p.UserID] {
			movedPenalties[p.UserID] = p
			delete(l.dynamic.penalties, tagUUID)
			l.dynamic.dirty = true
		} else if value, ok := l.UserLimitInfo.Load(tagUUID); ok {
			l.clearPenaltyLocked(tagUUID, value.(*UserLimitInfo), "revoked", time.Now())
		}
		if value, ok := l.SpeedLimiter.Load(tagUUID); ok {
			value.(*rate.Controller).Close()
		}
		l.UserLimitInfo.Delete(tagUUID)
		l.UserOnlineIP.Delete(tagUUID)
		l.SpeedLimiter.Delete(tagUUID)
		delete(l.dynamic.samples, tagUUID)
		delete(l.dynamic.penalties, tagUUID)
		delete(l.UUIDtoUID, deleted[i].Uuid)
		l.deleteAlive(deleted[i].Id)
	}
	for i := range added {
		tagUUID := format.UserTag(tag, added[i].Uuid)
		if user := l.onlineUsers[tagUUID]; user != nil && user.uid != added[i].Id {
			delete(l.onlineUsers, tagUUID)
		}
		userLimit := &UserLimitInfo{UID: added[i].Id}
		if previous, ok := l.UserLimitInfo.Load(tagUUID); ok {
			userLimit = previous.(*UserLimitInfo)
		}
		wasExempt := userLimit.DynamicSpeedExempt
		userLimit.SpeedLimit = added[i].SpeedLimit
		userLimit.DeviceLimit = added[i].DeviceLimit
		userLimit.DynamicSpeedExempt = added[i].DynamicSpeedExempt
		if p, moved := movedPenalties[userLimit.UID]; moved && !userLimit.DynamicSpeedExempt {
			l.dynamic.penalties[tagUUID] = p
			userLimit.DynamicSpeedLimit, userLimit.ExpireTime = p.LimitMbps, p.ExpiresAt
		}
		if userLimit.DynamicSpeedExempt {
			l.clearPenaltyLocked(tagUUID, userLimit, "exempt", time.Now())
			userLimit.DynamicSpeedLimit, userLimit.ExpireTime = 0, 0
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
		l.updateRateLocked(tagUUID, userLimit)
		if wasExempt != userLimit.DynamicSpeedExempt {
			l.resetSampleLocked(tagUUID, time.Now())
		}
	}
	l.persistDynamicLocked()
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	l.userMu.Lock()
	defer l.userMu.Unlock()
	if v, ok := l.UserLimitInfo.Load(format.UserTag(tag, uuid)); ok {
		info := v.(*UserLimitInfo)
		if info.DynamicSpeedExempt || l.dynamic.policy != nil {
			return nil
		}
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
		l.updateRateLocked(format.UserTag(tag, uuid), info)
	} else {
		return errors.New("not found")
	}
	return nil
}

// LimitedUserCount walks UserLimitInfo and returns how many users currently
// have an active speed cap — either a static SpeedLimit or an unexpired
// dynamic limit. The metrics task uses this to populate the destructive
// "X Limit" row in the admin popup.
func (l *Limiter) LimitedUserCount() int {
	l.userMu.RLock()
	defer l.userMu.RUnlock()
	now := time.Now().Unix()
	count := 0
	l.UserLimitInfo.Range(func(_, v any) bool {
		u, ok := v.(*UserLimitInfo)
		if !ok || u == nil {
			return true
		}
		if u.SpeedLimit > 0 {
			count++
			return true
		}
		if u.DynamicSpeedLimit > 0 && (u.ExpireTime == 0 || u.ExpireTime > now) {
			count++
		}
		return true
	})
	return count
}

// SetDeviceTolerance applies the panel-configured device-limit headroom.
// Negative values are clamped to zero.
func (l *Limiter) SetDeviceTolerance(tolerance int) {
	if tolerance < 0 {
		tolerance = 0
	}
	l.deviceTolerance.Store(int32(tolerance))
}

// SetIgnoredPrefixes replaces the operator ignore list. Entries are CIDR
// strings or bare addresses; malformed entries are skipped so a typo in
// the panel cannot disable the rest of the list.
func (l *Limiter) SetIgnoredPrefixes(entries []string) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	l.ignoredPrefixes.Store(&prefixes)
}

// isExempt reports whether ip must bypass device accounting: a CDN edge or
// an operator-ignored address. ip is expected to be unmapped already.
func (l *Limiter) isExempt(ip string) bool {
	if l.cdnPolicy.IsProxyIP(ip) {
		return true
	}
	prefixes := l.ignoredPrefixes.Load()
	if prefixes == nil || len(*prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range *prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (l *Limiter) SetDisabledCDNProviders(names []string) {
	l.cdnPolicy.SetDisabledProviders(names)
}

// MergeKickedList merges panel-issued kicks (uid → ip → remaining ttl in
// seconds) into the local table. Entries expire locally, so merging is safe
// against stale full syncs racing a fresh kick broadcast.
func (l *Limiter) MergeKickedList(kicked map[int]map[string]int64) {
	if len(kicked) == 0 {
		return
	}
	now := time.Now().Unix()

	l.kickedMu.Lock()
	defer l.kickedMu.Unlock()
	for uid, ips := range kicked {
		for ip, ttl := range ips {
			if ttl <= 0 {
				continue
			}
			if l.KickedIPs[uid] == nil {
				l.KickedIPs[uid] = make(map[string]int64)
			}
			expiry := now + ttl
			if expiry > l.KickedIPs[uid][ip] {
				l.KickedIPs[uid][ip] = expiry
			}
		}
	}
	// prune whatever already lapsed while we hold the lock
	for uid, ips := range l.KickedIPs {
		for ip, expiry := range ips {
			if expiry <= now {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(l.KickedIPs, uid)
		}
	}
}

func (l *Limiter) isKicked(uid int, ip string) bool {
	l.kickedMu.RLock()
	expiry, ok := l.KickedIPs[uid][ip]
	l.kickedMu.RUnlock()
	return ok && expiry > time.Now().Unix()
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *rate.Controller, Reject bool) {
	// Normalize mapped IPv4 so tracking and panel-issued kicks use one key.
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.Unmap().String()
	}
	isCdn := l.isExempt(ip)

	// check and gen speed limit Bucket
	deviceLimit := 0
	var uid int
	l.userMu.Lock()
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime <= time.Now().Unix() && u.ExpireTime != 0 && l.dynamic.policy == nil {
			u.DynamicSpeedLimit, u.ExpireTime = 0, 0
		}
		Bucket = l.rateForLocked(taguuid, u)
	} else {
		l.userMu.Unlock()
		return nil, true
	}
	l.userMu.Unlock()
	// Panel-kicked IPs are rejected before any bookkeeping so they never
	// re-enter the online table or re-occupy the freed device slot.
	if l.isKicked(uid, ip) {
		return nil, true
	}
	// Effective ceiling = device_limit + tolerance: headroom so a device
	// switching nodes/networks is not blocked by its own stale alive entry.
	effectiveLimit := deviceLimit + int(l.deviceTolerance.Load())
	if noSSUDP && !isCdn {
		l.onlineMu.Lock()
		defer l.onlineMu.Unlock()
		active, exists := l.UserOnlineIP.Load(taguuid)
		if !exists {
			active = new(sync.Map)
		}
		devices := active.(*sync.Map)
		currentUID, _ := devices.Load(ip)
		if currentUID != uid {
			var previousUID any
			if previous, exists := l.OldUserOnline.Load(taguuid); exists {
				previousUID, _ = previous.(*sync.Map).LoadAndDelete(ip)
			}
			if previousUID != uid && deviceLimit > 0 && effectiveLimit <= l.aliveCount(uid) {
				return nil, true
			}
			devices.Store(ip, uid)
			l.UserOnlineIP.Store(taguuid, devices)
		}
	}

	return Bucket, false
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	l.onlineMu.Lock()
	defer l.onlineMu.Unlock()
	onlineUser := l.onlineDevicesLocked()
	// Keep the admission cache's existing cycle; reports use live registrations.
	l.OldUserOnline, l.UserOnlineIP = l.UserOnlineIP, new(sync.Map)

	return &onlineUser, nil
}

// CountOnlineIP counts distinct authenticated user/IP pairs with live connections.
func (l *Limiter) CountOnlineIP() int {
	l.onlineMu.Lock()
	defer l.onlineMu.Unlock()
	count := 0
	for _, device := range l.onlineDevicesLocked() {
		if !l.isExempt(device.IP) {
			count++
		}
	}
	return count
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}

func (l *Limiter) UpdateAliveList(aliveList map[int]int) {
	l.aliveMu.Lock()
	l.AliveList = cloneAliveList(aliveList)
	l.aliveMu.Unlock()
}

func (l *Limiter) aliveCount(uid int) int {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	return l.AliveList[uid]
}

func (l *Limiter) deleteAlive(uid int) {
	l.aliveMu.Lock()
	delete(l.AliveList, uid)
	l.aliveMu.Unlock()
}

func cloneAliveList(aliveList map[int]int) map[int]int {
	cloned := make(map[int]int, len(aliveList))
	for uid, count := range aliveList {
		if count > 0 {
			cloned[uid] = count
		}
	}
	return cloned
}
