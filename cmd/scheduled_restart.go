package cmd

import (
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

type scheduledRestart struct {
	at time.Time
}

func (*scheduledRestart) Error() string {
	return "scheduled restart due; exiting for service manager restart"
}

type restartScheduler struct {
	mu         sync.Mutex
	configured bool
	options    conf.ScheduledRestartConfig
	eligible   time.Time
	next       time.Time
	start, end time.Duration
	location   *time.Location
}

func (s *restartScheduler) configure(options conf.ScheduledRestartConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configured && s.options == options {
		// Unrelated config/DNS reloads must not postpone maintenance forever.
		return
	}
	s.configured, s.options, s.next = true, options, time.Time{}
	if !options.Enabled {
		log.Info("Scheduled restart disabled")
		return
	}
	// Server and watcher validate these before applying the config.
	start, end, err := options.Window()
	if err != nil {
		log.WithError(err).Error("Invalid scheduled restart window")
		return
	}
	location, err := options.Location()
	if err != nil {
		log.WithError(err).Error("Invalid scheduled restart timezone")
		return
	}
	s.start, s.end, s.location = start, end, location
	s.eligible = time.Now().Add(time.Duration(options.IntervalDays) * 24 * time.Hour)
	s.next = nextRestartTime(s.eligible, start, end, location)
	s.logNext()
}

// nextRestartTime chooses a random whole minute in the first usable window
// after earliest. Construct each boundary in local time: adding 24 hours to
// midnight is incorrect across daylight-saving changes.
func nextRestartTime(earliest time.Time, start, end time.Duration, location *time.Location) time.Time {
	local := earliest.In(location)
	y, m, d := local.Date()
	for {
		first := time.Date(y, m, d, 0, 0, 0, 0, location)
		dayEnd := time.Date(y, m, d+1, 0, 0, 0, 0, location)
		if earliest.After(first) {
			first = earliest.Truncate(time.Minute)
			if first.Before(earliest) {
				first = first.Add(time.Minute)
			}
		}
		// Enumerating real minutes also handles skipped and repeated DST
		// hours without normalizing a missing boundary into another hour.
		var candidates []time.Time
		for candidate := first; candidate.Before(dayEnd); candidate = candidate.Add(time.Minute) {
			if inRestartWindow(candidate, start, end, location) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) > 0 {
			return candidates[rand.IntN(len(candidates))]
		}
		day := time.Date(y, m, d+1, 12, 0, 0, 0, location)
		y, m, d = day.Date()
	}
}

func inRestartWindow(now time.Time, start, end time.Duration, location *time.Location) bool {
	local := now.In(location)
	clock := time.Duration(local.Hour())*time.Hour + time.Duration(local.Minute())*time.Minute
	return clock >= start && clock < end
}

func (s *restartScheduler) due(now time.Time) *scheduledRestart {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next.IsZero() || now.Before(s.eligible) || now.Before(s.next) {
		return nil
	}
	if !inRestartWindow(now, s.start, s.end, s.location) {
		// A clock jump or suspended host must not cause a daytime restart.
		s.next = nextRestartTime(now, s.start, s.end, s.location)
		s.logNext()
		return nil
	}
	reason := &scheduledRestart{at: s.next}
	s.next = time.Time{}
	return reason
}

func (s *restartScheduler) logNext() {
	log.WithFields(log.Fields{
		"next_restart":  s.next.Format(time.RFC3339),
		"interval_days": s.options.IntervalDays,
		"timezone":      s.location.String(),
	}).Info("Scheduled restart planned")
}

func prepareScheduledRestart(reason *scheduledRestart, timeout time.Duration) {
	// Arm before logging: shutdown must finish even if a log writer stalls.
	time.AfterFunc(timeout, func() { os.Exit(1) })
	log.WithField("scheduled_at", reason.at.Format(time.RFC3339)).Warn("Scheduled restart due; stopping N2X for service manager restart")
}
