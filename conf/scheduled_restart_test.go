package conf

import "testing"

func TestScheduledRestartDefaultsAndOverrides(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings map[string]any
		want     ScheduledRestartConfig
	}{
		{"legacy stays off", nil, ScheduledRestartConfig{IntervalDays: 3, StartTime: "03:00", EndTime: "05:00"}},
		{"explicitly enable", map[string]any{"Enabled": true}, ScheduledRestartConfig{Enabled: true, IntervalDays: 3, StartTime: "03:00", EndTime: "05:00"}},
		{"custom", map[string]any{"Enabled": true, "IntervalDays": 7, "StartTime": "01:30", "EndTime": "02:45", "Timezone": "Asia/Shanghai"}, ScheduledRestartConfig{Enabled: true, IntervalDays: 7, StartTime: "01:30", EndTime: "02:45", Timezone: "Asia/Shanghai"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			if tt.settings != nil {
				doc["ScheduledRestart"] = tt.settings
			}
			c, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if c.ScheduledRestart != tt.want {
				t.Fatalf("schedule = %+v, want %+v", c.ScheduledRestart, tt.want)
			}
		})
	}
}

func TestScheduledRestartRejectsInvalidConfig(t *testing.T) {
	for _, tt := range []struct {
		settings map[string]any
		path     string
	}{
		{map[string]any{"IntervalDays": 0}, "ScheduledRestart.IntervalDays"},
		{map[string]any{"IntervalDays": -1}, "ScheduledRestart.IntervalDays"},
		{map[string]any{"IntervalDays": 3651}, "ScheduledRestart.IntervalDays"},
		{map[string]any{"IntervalDays": 1.5}, "ScheduledRestart.IntervalDays"},
		{map[string]any{"StartTime": "3:00"}, "ScheduledRestart.StartTime"},
		{map[string]any{"StartTime": "24:00"}, "ScheduledRestart.StartTime"},
		{map[string]any{"EndTime": "05:60"}, "ScheduledRestart.EndTime"},
		{map[string]any{"EndTime": "03:00"}, "ScheduledRestart.EndTime"},
		{map[string]any{"StartTime": "23:00", "EndTime": "02:00"}, "ScheduledRestart.EndTime"},
		{map[string]any{"Timezone": "Unknown/Zone"}, "ScheduledRestart.Timezone"},
		{map[string]any{"Enable": true}, "ScheduledRestart.Enable"},
	} {
		doc := validDoc()
		doc["ScheduledRestart"] = tt.settings
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		assertIssue(t, err, tt.path)
	}
}
