package limiter

import "github.com/Designdocs/N2X/common/domainusage"

func (l *Limiter) TrackDomain(user, host string) (*domainusage.Flow, func()) {
	store := l.DomainUsage.Load()
	if store == nil {
		return nil, nil
	}
	value, ok := l.UserLimitInfo.Load(user)
	if !ok {
		return nil, nil
	}
	l.userMu.RLock()
	info := value.(*UserLimitInfo)
	uid := info.DomainUserID
	if uid <= 0 {
		uid = info.UID
	}
	l.userMu.RUnlock()
	return store.Track(uid, host)
}
