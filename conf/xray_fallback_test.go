package conf

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Designdocs/N2X/decoy"
)

// DecoyFallback is the one-switch form of EnableFallback: it must turn fallback
// on by itself, so an operator never has to hand-write a FallBackConfigs entry
// just to put a page on port 443.
func TestFallbackEnabled(t *testing.T) {
	tests := []struct {
		name    string
		options *XrayOptions
		want    bool
	}{
		{name: "nil options", options: nil, want: false},
		{name: "both off", options: &XrayOptions{}, want: false},
		{name: "explicit fallback", options: &XrayOptions{EnableFallback: true}, want: true},
		{name: "decoy switch", options: &XrayOptions{DecoyFallback: true}, want: true},
		{name: "both on", options: &XrayOptions{EnableFallback: true, DecoyFallback: true}, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.options.FallbackEnabled(); got != test.want {
				t.Fatalf("FallbackEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestResolvedFallbackConfigs(t *testing.T) {
	custom := []FallBackConfigForXray{{Dest: "127.0.0.1:8080", Alpn: "http/1.1"}}
	decoyEntry := []FallBackConfigForXray{{Dest: decoy.Selector}}

	tests := []struct {
		name    string
		options *XrayOptions
		want    []FallBackConfigForXray
	}{
		{name: "nil options", options: nil, want: nil},
		{name: "nothing configured", options: &XrayOptions{EnableFallback: true}, want: nil},
		{
			name:    "decoy switch synthesises an entry",
			options: &XrayOptions{DecoyFallback: true},
			want:    decoyEntry,
		},
		{
			name:    "explicit entries win over the decoy switch",
			options: &XrayOptions{DecoyFallback: true, FallBackConfigs: custom},
			want:    custom,
		},
		{
			name:    "explicit entries kept without the decoy switch",
			options: &XrayOptions{EnableFallback: true, FallBackConfigs: custom},
			want:    custom,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.options.ResolvedFallbackConfigs(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ResolvedFallbackConfigs() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// ResolvedFallbackConfigs must not write through to the stored slice, otherwise
// a config reload would accumulate synthesised entries.
func TestResolvedFallbackConfigsDoesNotMutateOptions(t *testing.T) {
	options := &XrayOptions{DecoyFallback: true}

	first := options.ResolvedFallbackConfigs()
	first[0].Dest = "mutated"

	if second := options.ResolvedFallbackConfigs(); second[0].Dest != decoy.Selector {
		t.Fatalf("second call returned %q, want %q", second[0].Dest, decoy.Selector)
	}
	if options.FallBackConfigs != nil {
		t.Fatalf("FallBackConfigs = %+v, want nil", options.FallBackConfigs)
	}
}

func TestDecoyFallbackParsedFromNodeOptions(t *testing.T) {
	options := &Options{}
	raw := `{"Core":"xray","NodeType":"vless","DecoyFallback":true}`

	if err := json.Unmarshal([]byte(raw), options); err != nil {
		t.Fatalf("unmarshal node options: %v", err)
	}
	if options.XrayOptions == nil {
		t.Fatal("XrayOptions = nil, want parsed options")
	}
	if !options.XrayOptions.DecoyFallback {
		t.Fatal("DecoyFallback = false, want true")
	}
	if !options.XrayOptions.FallbackEnabled() {
		t.Fatal("FallbackEnabled() = false, want true")
	}
}
