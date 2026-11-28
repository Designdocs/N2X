package node

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Designdocs/N2X/common/domainusage"
	log "github.com/sirupsen/logrus"
)

const domainCheckPeriod = 5 * time.Second

type domainMonitor struct {
	owner                         *Controller
	path, disabledFile            string
	previous                      string
	low                           bool
	retryAt, maintainAt, nextHour time.Time
	free                          func(string) (int64, error)
}

func (c *Controller) startDomainUsage() {
	dir := os.Getenv("N2X_DOMAIN_USAGE_DIR")
	if dir == "" {
		dir = "/var/lib/N2X/domain-usage"
	}
	configDir := os.Getenv("N2X_CONFIG_DIR")
	if configDir == "" {
		configDir = "/etc/N2X"
	}
	identity := fmt.Sprintf("%s|%d|%s", c.apiClient.APIHost, c.apiClient.NodeId, c.apiClient.InstanceID)
	m := domainMonitor{owner: c, path: filepath.Join(dir, fmt.Sprintf("%x.db", sha256.Sum256([]byte(identity)))), disabledFile: filepath.Join(configDir, "domain-usage.disabled"), free: domainusage.FreeBytes}
	c.domainStop = make(chan struct{})
	c.domainDone = make(chan struct{})
	go func() {
		defer close(c.domainDone)
		m.tick(time.Now())
		for {
			now := time.Now()
			wait := domainCheckPeriod
			if !m.nextHour.IsZero() {
				wait = min(wait, m.nextHour.Sub(now))
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				m.tick(time.Now())
			case <-c.domainStop:
				timer.Stop()
				m.tick(time.Now()) // honour a new off switch or low disk before the final write
				if s := c.apiClient.Domains.Store.Swap(nil); s != nil {
					c.limiter.DomainUsage.Store(nil)
					if err := s.Close(time.Now()); err != nil {
						log.WithError(err).Warn("Close domain usage")
					}
				}
				return
			}
		}
	}()
}
func (c *Controller) closeDomainUsage() {
	if c.domainStop != nil {
		close(c.domainStop)
		<-c.domainDone
	}
}
func (m *domainMonitor) suspend(state string, err error) {
	d := &m.owner.apiClient.Domains
	d.Paused.Store(true)
	if s := d.Store.Swap(nil); s != nil {
		m.owner.limiter.DomainUsage.Store(nil)
		s.Pause()
	}
	d.ClearQuery()
	m.nextHour = time.Time{}
	if state != m.previous {
		entry := log.WithField("tag", m.owner.tag).WithField("reason", state)
		if err != nil {
			entry.WithError(err).Warn("Domain statistics paused")
		} else {
			entry.Info("Domain statistics disabled")
		}
		m.previous = state
	}
}
func (m *domainMonitor) tick(now time.Time) {
	if !now.Before(m.maintainAt) {
		m.maintainAt = now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		if err := domainusage.Maintain(m.path, now); err != nil {
			log.WithError(err).Warn("Maintain domain usage directory")
		}
	}
	if _, err := os.Lstat(m.disabledFile); !os.IsNotExist(err) {
		m.suspend("manual", err)
		m.retryAt = time.Time{}
		return
	}
	d := &m.owner.apiClient.Domains
	rate := d.Rate()
	if rate == nil {
		return
	}
	if now.Before(m.retryAt) {
		return
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		m.failure(now, err)
		return
	}
	free, err := m.free(dir)
	if err != nil {
		m.failure(now, err)
		return
	}
	if free <= domainusage.MinFreeBytes || m.low && free < domainusage.ResumeFreeBytes {
		m.low = true
		m.suspend("disk space", domainusage.ErrLowDisk)
		return
	}
	m.low = false
	s := d.Store.Load()
	if s == nil {
		s, err = domainusage.Open(m.path, *rate)
		if err != nil {
			m.failure(now, err)
			return
		}
		d.Paused.Store(false)
		d.Store.Store(s)
		m.owner.limiter.DomainUsage.Store(s)
		m.nextHour = now.UTC().Truncate(time.Hour).Add(time.Hour)
		if m.previous != "" {
			log.WithField("tag", m.owner.tag).Info("Domain statistics resumed")
		}
		m.previous = ""
		return
	}
	if s.MemoryFull() {
		// Preserve this hour's admitted entries before shedding collection.
		if err := s.Flush(now); err != nil {
			m.failure(now, err)
			return
		}
		m.failure(now, domainusage.ErrMemoryLimit)
		return
	}
	if !now.Before(m.nextHour) {
		end := now.UTC().Truncate(time.Hour)
		if err := s.FlushHour(end); err != nil {
			m.failure(now, err)
			return
		}
		m.nextHour = end.Add(time.Hour)
	}
}
func (m *domainMonitor) failure(now time.Time, err error) {
	state := "storage error"
	m.retryAt = now.Add(time.Minute)
	switch {
	case errors.Is(err, domainusage.ErrDiskLimit):
		state = "daily capacity"
		m.retryAt = now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	case errors.Is(err, domainusage.ErrLowDisk):
		state = "disk space"
		m.low = true
	case errors.Is(err, domainusage.ErrMemoryLimit):
		state = "in-memory capacity"
		m.retryAt = now.UTC().Truncate(time.Hour).Add(time.Hour)
	}
	m.suspend(state, err)
}
