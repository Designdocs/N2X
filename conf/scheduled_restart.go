package conf

import (
	"errors"
	"time"
	_ "time/tzdata" // Keep named timezones available on minimal installations.
)

// ScheduledRestartConfig schedules a process restart after a minimum uptime,
// within a local daily window. The zero Enabled value keeps legacy configs off.
type ScheduledRestartConfig struct {
	Enabled      bool   `json:"Enabled"`
	IntervalDays int    `json:"IntervalDays"`
	StartTime    string `json:"StartTime"`
	EndTime      string `json:"EndTime"`
	Timezone     string `json:"Timezone"`
}

func parseRestartTime(value string) (time.Duration, error) {
	t, err := time.Parse("15:04", value)
	if err != nil || t.Format("15:04") != value {
		return 0, errors.New("must be a time in HH:MM format (00:00..23:59)")
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

func (c ScheduledRestartConfig) Window() (start, end time.Duration, err error) {
	if start, err = parseRestartTime(c.StartTime); err != nil {
		return
	}
	if end, err = parseRestartTime(c.EndTime); err != nil {
		return
	}
	if end <= start {
		err = errors.New("EndTime must be later than StartTime within the same day")
	}
	return
}

func (c ScheduledRestartConfig) Location() (*time.Location, error) {
	if c.Timezone == "" {
		return time.Local, nil
	}
	return time.LoadLocation(c.Timezone)
}

func (v *validator) checkScheduledRestart(c ScheduledRestartConfig) {
	if c.IntervalDays < 1 || c.IntervalDays > 3650 {
		v.add("ScheduledRestart.IntervalDays", "must be between 1 and 3650 days")
	}
	start, startErr := parseRestartTime(c.StartTime)
	end, endErr := parseRestartTime(c.EndTime)
	if startErr != nil {
		v.add("ScheduledRestart.StartTime", "%v", startErr)
	}
	if endErr != nil {
		v.add("ScheduledRestart.EndTime", "%v", endErr)
	}
	if startErr == nil && endErr == nil && end <= start {
		v.add("ScheduledRestart.EndTime", "must be later than StartTime within the same day")
	}
	if _, err := c.Location(); err != nil {
		v.add("ScheduledRestart.Timezone", "unknown timezone %q", c.Timezone)
	}
}
