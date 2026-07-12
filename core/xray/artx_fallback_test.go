package xray

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
)

func TestResolveArtXFallback(t *testing.T) {
	tests := []struct {
		name       string
		config     panel.ArtXFallback
		listen     string
		wantOrigin string
		wantNil    bool
		wantError  bool
	}{
		{
			name:    "disabled",
			config:  panel.ArtXFallback{Enabled: false, Origin: "http://unsafe.example.com/"},
			wantNil: true,
		},
		{
			name:       "installed decoy default",
			config:     panel.ArtXFallback{Enabled: true, Origin: artXDecoySelector},
			wantOrigin: "http://127.0.0.1:60443/",
		},
		{
			name:       "installed decoy custom loopback",
			config:     panel.ArtXFallback{Enabled: true, Origin: artXDecoySelector},
			listen:     "127.0.0.1:61443",
			wantOrigin: "http://127.0.0.1:61443/",
		},
		{
			name:       "installed decoy IPv6 loopback",
			config:     panel.ArtXFallback{Enabled: true, Origin: artXDecoySelector},
			listen:     "[::1]:61443",
			wantOrigin: "http://[::1]:61443/",
		},
		{
			name:       "explicit HTTPS",
			config:     panel.ArtXFallback{Enabled: true, Origin: "https://origin.example.com/status?source=edge"},
			wantOrigin: "https://origin.example.com/status?source=edge",
		},
		{
			name:      "installed decoy wildcard rejected",
			config:    panel.ArtXFallback{Enabled: true, Origin: artXDecoySelector},
			listen:    "0.0.0.0:60443",
			wantError: true,
		},
		{
			name:      "installed decoy non-loopback rejected",
			config:    panel.ArtXFallback{Enabled: true, Origin: artXDecoySelector},
			listen:    "192.0.2.1:60443",
			wantError: true,
		},
		{
			name:      "enabled empty origin rejected",
			config:    panel.ArtXFallback{Enabled: true},
			wantError: true,
		},
		{
			name:      "explicit HTTP rejected",
			config:    panel.ArtXFallback{Enabled: true, Origin: "http://origin.example.com/"},
			wantError: true,
		},
		{
			name:      "explicit credentials rejected",
			config:    panel.ArtXFallback{Enabled: true, Origin: "https://user:pass@origin.example.com/"},
			wantError: true,
		},
		{
			name:      "explicit fragment rejected",
			config:    panel.ArtXFallback{Enabled: true, Origin: "https://origin.example.com/#private"},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(artXDecoyListenEnvironment, test.listen)

			got, err := resolveArtXFallback(test.config)
			if (err != nil) != test.wantError {
				t.Fatalf("resolveArtXFallback() error = %v, wantError %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if test.wantNil {
				if got != nil {
					t.Fatalf("resolveArtXFallback() = %+v, want nil", got)
				}
				return
			}
			if got == nil || !got.Enabled || got.Origin != test.wantOrigin {
				t.Fatalf("resolveArtXFallback() = %+v, want enabled origin %q", got, test.wantOrigin)
			}
		})
	}
}
