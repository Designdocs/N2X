package conf

import "testing"

func TestMemoryConfigDefaultsAndOverrides(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings map[string]any
		want     MemoryConfig
	}{
		{"legacy", nil, MemoryConfig{SoftLimitPercent: 70, RestartPercent: 90}},
		{"partial", map[string]any{"RestartPercent": 85}, MemoryConfig{SoftLimitPercent: 70, RestartPercent: 85}},
		{"disabled", map[string]any{"SoftLimitPercent": 0, "RestartPercent": 0}, MemoryConfig{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			if tt.settings != nil {
				doc["Memory"] = tt.settings
			}
			c, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if c.MemoryConfig != tt.want {
				t.Fatalf("memory = %+v, want %+v", c.MemoryConfig, tt.want)
			}
		})
	}
}

func TestMemoryConfigRejectsInvalidThresholds(t *testing.T) {
	for _, tt := range []struct {
		settings map[string]any
		path     string
	}{
		{map[string]any{"RestartPercent": -1}, "Memory.RestartPercent"},
		{map[string]any{"RestartPercent": 100}, "Memory.RestartPercent"},
		{map[string]any{"SoftLimitPercent": -1}, "Memory.SoftLimitPercent"},
		{map[string]any{"SoftLimitPercent": 100}, "Memory.SoftLimitPercent"},
		{map[string]any{"SoftLimitPercent": 90, "RestartPercent": 90}, "Memory.SoftLimitPercent"},
	} {
		doc := validDoc()
		doc["Memory"] = tt.settings
		_, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
		assertIssue(t, err, tt.path)
	}
}
