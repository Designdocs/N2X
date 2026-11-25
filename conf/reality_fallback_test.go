package conf

import (
	"math"
	"strings"
	"testing"
)

func TestValidateRealityFallbackLimits(t *testing.T) {
	for _, tc := range []struct {
		name, coreType, pin, coreName string
		value                         any
		wantError                     string
	}{
		{"xray", "xray", "xray", "", 32768, ""},
		{"auto_xray", "xray", "", "", 32768, ""},
		{"named_xray", "xray", "", "primary", 32768, ""},
		{"zero_rate", "xray", "xray", "", 0, ""},
		{"signed_overflow", "xray", "xray", "", uint64(math.MaxInt64) + 1, "64-bit"},
		{"negative", "xray", "xray", "", -1, "uint64"},
		{"sing", "sing", "sing", "", 32768, "sing-box"},
		{"auto_sing", "sing", "", "", 32768, "sing-box"},
		{"named_sing", "sing", "", "primary", 0, "sing-box"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := validDoc()
			core := docCore(doc, 0)
			core["Type"], core["Name"] = tc.coreType, "primary"
			node := docNode(doc, 0)
			// Exercise nested options as well as the flat form used by the wire tests.
			delete(node, "Core")
			node["Options"] = map[string]any{
				"Core": tc.pin, "CoreName": tc.coreName,
				"limitFallbackDownload": map[string]any{"afterBytes": 4096, "bytesPerSec": tc.value, "burstBytesPerSec": 65536},
			}
			cfg, err := LoadValidated(writeDoc(t, doc), ValidateOptions{})
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected error containing %q, got %v", tc.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			opts := cfg.NodeConfig[0].Options
			want := RealityFallbackLimit{AfterBytes: 4096, BytesPerSec: uint64(tc.value.(int)), BurstBytesPerSec: 65536}
			if opts.LimitFallbackDownload == nil || *opts.LimitFallbackDownload != want || opts.LimitFallbackUpload != nil {
				t.Fatalf("unexpected limits: up=%+v down=%+v", opts.LimitFallbackUpload, opts.LimitFallbackDownload)
			}
		})
	}
}
