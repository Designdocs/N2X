package limiter

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/rate"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

type speedSample struct {
	total int64
	at    time.Time
	above time.Duration
}
type activePenalty struct {
	panel.DynamicSpeedPenalty
	until time.Time
}
type dynamicState struct {
	policy    *conf.NodeDynamicSpeedPolicy
	samples   map[string]speedSample
	penalties map[string]activePenalty
	events    []panel.DynamicSpeedEvent
	released  []string
	file      string
	loaded    bool
	dirty     bool
	err       string
	policyErr string
	stopped   bool
}

func (l *Limiter) effectiveRateLocked(u *UserLimitInfo) int64 {
	dynamic := u.DynamicSpeedLimit
	if u.DynamicSpeedExempt {
		dynamic = 0
	}
	return int64(determineSpeedLimit(l.SpeedLimit, determineSpeedLimit(u.SpeedLimit, dynamic))) * 1000000 / 8
}

func (l *Limiter) rateForLocked(key string, u *UserLimitInfo) *rate.Controller {
	if v, ok := l.SpeedLimiter.Load(key); ok {
		c := v.(*rate.Controller)
		c.SetRate(l.effectiveRateLocked(u))
		return c
	}
	c := rate.NewController(l.effectiveRateLocked(u))
	l.SpeedLimiter.Store(key, c)
	if l.dynamic.samples == nil {
		l.dynamic.samples = make(map[string]speedSample)
	}
	l.dynamic.samples[key] = speedSample{at: time.Now()}
	return c
}

func (l *Limiter) updateRateLocked(key string, u *UserLimitInfo) {
	if v, ok := l.SpeedLimiter.Load(key); ok {
		v.(*rate.Controller).SetRate(l.effectiveRateLocked(u))
	}
}

// ConfigureDynamic is idempotent. Changing durations never extends existing
// penalties. A disabled policy explicitly releases panel and legacy limits.
func (l *Limiter) ConfigureDynamic(policy *conf.NodeDynamicSpeedPolicy, commands []conf.DynamicSpeedCommand, file string) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	l.userMu.Lock()
	defer l.userMu.Unlock()
	now := time.Now()
	s := &l.dynamic
	if s.samples == nil {
		s.samples = make(map[string]speedSample)
	}
	if s.penalties == nil {
		s.penalties = make(map[string]activePenalty)
	}
	if policy == nil && s.policy != nil {
		s.policyErr = "panel omitted its managed dynamic speed policy"
		return nil
	}
	if policy != nil {
		s.policyErr = ""
	}
	old := s.policy
	if policy != nil {
		copy := *policy
		s.policy = &copy
	}
	if file != "" {
		s.file = file
	}
	if policy != nil && !s.loaded {
		s.loaded = true
		l.restoreDynamicLocked(now)
	}
	if policy != nil && !reflect.DeepEqual(old, policy) {
		reset := old == nil || old.Enabled != policy.Enabled || old.ThresholdMbps != policy.ThresholdMbps || old.SustainSeconds != policy.SustainSeconds
		l.UserLimitInfo.Range(func(k, v any) bool {
			key, u := k.(string), v.(*UserLimitInfo)
			if !policy.Enabled || u.DynamicSpeedExempt {
				l.clearPenaltyLocked(key, u, "disabled", now)
				u.DynamicSpeedLimit, u.ExpireTime = 0, 0
			} else if p, ok := s.penalties[key]; ok {
				p.LimitMbps = policy.LimitMbps
				s.penalties[key] = p
				u.DynamicSpeedLimit = policy.LimitMbps
				s.dirty = true
			}
			l.updateRateLocked(key, u)
			if reset {
				l.resetSampleLocked(key, now)
			}
			return true
		})
	}
	for _, command := range commands {
		if command.ID == "" || command.PenaltyID == "" || command.ExpiresAt <= now.Unix() {
			continue
		}
		for key, p := range s.penalties {
			if p.UserID != command.UserID || p.ID != command.PenaltyID {
				continue
			}
			if v, ok := l.UserLimitInfo.Load(key); ok {
				l.clearPenaltyLocked(key, v.(*UserLimitInfo), "released", now)
			}
			s.released = append(s.released, command.ID)
			if len(s.released) > 32 {
				s.released = s.released[len(s.released)-32:]
			}
			s.dirty = true
			break
		}
	}
	l.persistDynamicLocked()
	return nil
}

func (l *Limiter) resetSampleLocked(key string, now time.Time) {
	var total int64
	if v, ok := l.SpeedLimiter.Load(key); ok {
		total = v.(*rate.Controller).Total()
	}
	if l.dynamic.samples != nil {
		l.dynamic.samples[key] = speedSample{total: total, at: now}
	}
}

func (l *Limiter) clearPenaltyLocked(key string, u *UserLimitInfo, reason string, now time.Time) {
	if p, ok := l.dynamic.penalties[key]; ok {
		delete(l.dynamic.penalties, key)
		l.dynamicEventLocked(p, reason, now)
	}
	u.DynamicSpeedLimit, u.ExpireTime = 0, 0
	l.updateRateLocked(key, u)
	l.resetSampleLocked(key, now)
}

func (l *Limiter) dynamicEventLocked(p activePenalty, kind string, now time.Time) {
	s := &l.dynamic
	s.events = append(s.events, panel.DynamicSpeedEvent{ID: p.ID + ":" + kind, PenaltyID: p.ID, UserID: p.UserID, Kind: kind, At: now.Unix()})
	if len(s.events) > 50 {
		s.events = s.events[len(s.events)-50:]
	}
	s.dirty = true
	log.WithFields(log.Fields{"user_id": p.UserID, "penalty_id": p.ID, "limit_mbps": p.LimitMbps, "expires_at": p.ExpiresAt}).Info("Dynamic speed limit " + kind)
}

// SampleDynamic uses monotonic elapsed time and non-resetting counters owned
// by the forwarding wrappers. Billing drains cannot affect this detector.
func (l *Limiter) SampleDynamic(now time.Time) {
	l.userMu.Lock()
	defer l.userMu.Unlock()
	s := &l.dynamic
	if s.stopped {
		return
	}
	for key, p := range s.penalties {
		if !now.Before(p.until) {
			if v, ok := l.UserLimitInfo.Load(key); ok {
				l.clearPenaltyLocked(key, v.(*UserLimitInfo), "expired", now)
			}
		}
	}
	l.SpeedLimiter.Range(func(k, v any) bool {
		key, controller := k.(string), v.(*rate.Controller)
		value, exists := l.UserLimitInfo.Load(key)
		if !exists {
			return true
		}
		u := value.(*UserLimitInfo)
		if s.policy == nil || !s.policy.Enabled || u.DynamicSpeedExempt {
			if s.policy == nil && u.ExpireTime > 0 && now.Unix() >= u.ExpireTime {
				u.DynamicSpeedLimit, u.ExpireTime = 0, 0
				l.updateRateLocked(key, u)
			}
			return true
		}
		if _, penalized := s.penalties[key]; penalized {
			return true
		}
		previous := s.samples[key]
		current := speedSample{total: controller.Total(), at: now}
		elapsed := now.Sub(previous.at)
		if !previous.at.IsZero() && elapsed > 0 && elapsed <= 2*conf.DynamicSpeedSampleSeconds*time.Second && current.total >= previous.total {
			mbps := float64(current.total-previous.total) * 8 / elapsed.Seconds() / 1000000
			if mbps > float64(s.policy.ThresholdMbps) {
				current.above = previous.above + elapsed
			}
			if current.above >= time.Duration(s.policy.SustainSeconds)*time.Second {
				until := now.Add(time.Duration(s.policy.PenaltySeconds) * time.Second)
				p := activePenalty{DynamicSpeedPenalty: panel.DynamicSpeedPenalty{ID: rand.Text(), UserID: u.UID, StartedAt: now.Unix(), ExpiresAt: until.Unix(), LimitMbps: s.policy.LimitMbps, MeasuredMbps: mbps, Revision: s.policy.Revision}, until: until}
				s.penalties[key] = p
				u.DynamicSpeedLimit, u.ExpireTime = p.LimitMbps, p.ExpiresAt
				l.updateRateLocked(key, u)
				l.dynamicEventLocked(p, "triggered", now)
				current.above = 0
			}
		}
		s.samples[key] = current
		return true
	})
	l.persistDynamicLocked()
}

// Fence the previous limiter before a replacement loads its state file. A
// sampler that already retained this pointer will then stop without writing.
func (l *Limiter) StopDynamicSampling() {
	l.userMu.Lock()
	defer l.userMu.Unlock()
	l.dynamic.stopped = true
	l.persistDynamicLocked()
}

type persistedDynamicState struct {
	Version   int                         `json:"version"`
	Penalties []panel.DynamicSpeedPenalty `json:"penalties"`
	Events    []panel.DynamicSpeedEvent   `json:"events"`
	Released  []string                    `json:"released_commands"`
}

func (l *Limiter) persistDynamicLocked() {
	s := &l.dynamic
	if !s.dirty || s.file == "" {
		return
	}
	state := persistedDynamicState{Version: 1, Events: s.events, Released: s.released}
	for _, p := range s.penalties {
		state.Penalties = append(state.Penalties, p.DynamicSpeedPenalty)
	}
	data, err := json.Marshal(state)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(s.file), 0700)
	}
	if err == nil {
		var file *os.File
		file, err = os.CreateTemp(filepath.Dir(s.file), ".dynamic-*")
		if err == nil {
			temporary := file.Name()
			if err = file.Chmod(0600); err == nil {
				_, err = file.Write(data)
			}
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(temporary, s.file)
			}
			if err != nil {
				_ = os.Remove(temporary)
			}
		}
	}
	if err != nil {
		message := fmt.Sprintf("persist dynamic speed state: %v", err)
		if s.err != message {
			log.WithError(err).Warn("Persist dynamic speed state failed")
		}
		s.err = message
		return
	}
	s.err, s.dirty = "", false
}

func (l *Limiter) restoreDynamicLocked(now time.Time) {
	s := &l.dynamic
	if s.file == "" {
		return
	}
	data, err := os.ReadFile(s.file)
	if os.IsNotExist(err) {
		return
	}
	var state persistedDynamicState
	if err == nil && len(data) > 4*1024*1024 {
		err = fmt.Errorf("state exceeds 4 MiB")
	}
	if err == nil {
		err = json.Unmarshal(data, &state)
	}
	if err != nil || state.Version != 1 {
		s.err = fmt.Sprintf("read dynamic speed state: %v (version %d)", err, state.Version)
		log.WithField("error", s.err).Warn("Dynamic speed state recovery failed; collecting fresh observations")
		return
	}
	s.events, s.released = state.Events, state.Released
	if len(s.events) > 50 {
		s.events = s.events[len(s.events)-50:]
	}
	if len(s.released) > 32 {
		s.released = s.released[len(s.released)-32:]
	}
	if !s.policy.Enabled {
		s.dirty = true
		return
	}
	byID := make(map[int]panel.DynamicSpeedPenalty)
	for _, p := range state.Penalties {
		if p.ID != "" && p.ExpiresAt > now.Unix() && p.ExpiresAt-now.Unix() <= 86400 {
			byID[p.UserID] = p
		}
	}
	l.UserLimitInfo.Range(func(k, v any) bool {
		key, u := k.(string), v.(*UserLimitInfo)
		if p, ok := byID[u.UID]; ok && !u.DynamicSpeedExempt {
			p.LimitMbps = s.policy.LimitMbps
			s.penalties[key] = activePenalty{DynamicSpeedPenalty: p, until: now.Add(time.Duration(p.ExpiresAt-now.Unix()) * time.Second)}
			u.DynamicSpeedLimit, u.ExpireTime = p.LimitMbps, p.ExpiresAt
		}
		return true
	})
}

func (l *Limiter) DynamicSpeedStatus() *panel.DynamicSpeedStatus {
	l.userMu.RLock()
	defer l.userMu.RUnlock()
	s := &l.dynamic
	status := &panel.DynamicSpeedStatus{Version: 1, SampleSeconds: conf.DynamicSpeedSampleSeconds, StateError: s.err, Penalties: []panel.DynamicSpeedPenalty{}, Events: append([]panel.DynamicSpeedEvent{}, s.events...), ReleasedCommands: append([]string{}, s.released...)}
	status.PolicyError = s.policyErr
	if s.policy != nil {
		status.Enabled, status.AppliedRevision = s.policy.Enabled, s.policy.Revision
	}
	status.LimitedUsers = len(s.penalties)
	for _, sample := range s.samples {
		if sample.above > 0 {
			status.ObservingUsers++
		}
	}
	for _, penalty := range s.penalties {
		status.Penalties = append(status.Penalties, penalty.DynamicSpeedPenalty)
	}
	sort.Slice(status.Penalties, func(i, j int) bool { return status.Penalties[i].UserID < status.Penalties[j].UserID })
	if len(status.Penalties) > 200 {
		status.Penalties = status.Penalties[:200]
	}
	return status
}
