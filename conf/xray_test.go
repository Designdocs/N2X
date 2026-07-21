package conf

import (
	"encoding/json"
	"testing"
)

// The extra BT sniffers must be on unless the operator explicitly turns them
// off. XrayConfig.UnmarshalJSON decodes into a zero struct, so a plain bool
// would silently default to false for every existing config file.
func TestBTExtraSniffingDefaultsToEnabled(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "absent from an existing config",
			raw:  `{"Log":{"Level":"error"},"RouteConfigPath":"/etc/N2X/route.json"}`,
			want: true,
		},
		{
			name: "explicitly enabled",
			raw:  `{"EnableBTExtraSniffing":true}`,
			want: true,
		},
		{
			name: "explicitly disabled",
			raw:  `{"EnableBTExtraSniffing":false}`,
			want: false,
		},
		{
			name: "empty object",
			raw:  `{}`,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewXrayConfig()
			if err := json.Unmarshal([]byte(tt.raw), c); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := c.BTExtraSniffingEnabled(); got != tt.want {
				t.Errorf("BTExtraSniffingEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A zero-valued XrayConfig must not report the feature as disabled.
func TestBTExtraSniffingEnabledOnZeroValue(t *testing.T) {
	var c XrayConfig
	if !c.BTExtraSniffingEnabled() {
		t.Error("zero-valued XrayConfig reported the extra BT sniffers as disabled")
	}
}
