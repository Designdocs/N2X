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

// A core entry that omits ConnectionConfig must keep the built-in defaults.
// Decoding used to start from a zero value and drop them, leaving a nil
// ConnectionConfig that crashed core/xray at startup.
func TestCoreConfigKeepsXrayDefaultsWhenKeysOmitted(t *testing.T) {
	c := CoreConfig{}
	if err := c.UnmarshalJSON([]byte(`{"Type":"xray","Log":{"Level":"warning"}}`)); err != nil {
		t.Fatalf("unmarshal core config: %v", err)
	}
	if c.XrayConfig == nil {
		t.Fatal("XrayConfig is nil")
	}
	if c.XrayConfig.ConnectionConfig == nil {
		t.Fatal("ConnectionConfig was dropped; core/xray would panic on this config")
	}
	if got := c.XrayConfig.ConnectionConfig.BufferSize; got != 64 {
		t.Fatalf("default BufferSize = %d, want 64", got)
	}
	if got := c.XrayConfig.AssetPath; got != "/etc/N2X/" {
		t.Fatalf("default AssetPath = %q", got)
	}
	// Values that were present must still win over the defaults.
	if got := c.XrayConfig.LogConfig.Level; got != "warning" {
		t.Fatalf("LogConfig.Level = %q, want the supplied value", got)
	}
}

// Explicit values must still override the defaults.
func TestCoreConfigXrayExplicitValuesWin(t *testing.T) {
	c := CoreConfig{}
	raw := `{"Type":"xray","AssetPath":"/opt/geo","ConnectionConfig":{"bufferSize":128,"handshake":9}}`
	if err := c.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatalf("unmarshal core config: %v", err)
	}
	if c.XrayConfig.AssetPath != "/opt/geo" {
		t.Fatalf("AssetPath = %q", c.XrayConfig.AssetPath)
	}
	if c.XrayConfig.ConnectionConfig.BufferSize != 128 || c.XrayConfig.ConnectionConfig.Handshake != 9 {
		t.Fatalf("ConnectionConfig = %#v", c.XrayConfig.ConnectionConfig)
	}
}

func TestCoreConfigSing(t *testing.T) {
	c := CoreConfig{}
	if err := c.UnmarshalJSON([]byte(`{"Type":"sing","Log":{"Level":"debug"},"NTP":{"Enable":true}}`)); err != nil {
		t.Fatalf("unmarshal core config: %v", err)
	}
	if c.SingConfig == nil {
		t.Fatal("SingConfig is nil")
	}
	if c.SingConfig.LogConfig.Level != "debug" {
		t.Fatalf("log level = %q", c.SingConfig.LogConfig.Level)
	}
	if !c.SingConfig.NtpConfig.Enable {
		t.Fatal("NTP.Enable was not decoded")
	}
	// Untouched defaults must survive.
	if c.SingConfig.NtpConfig.Server != "time.apple.com" {
		t.Fatalf("default NTP server = %q", c.SingConfig.NtpConfig.Server)
	}
}
