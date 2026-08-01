package decoy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseContentProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  string
		want   contentProfile
		wantOK bool
	}{
		{name: "balanced", value: "balanced", want: contentProfileBalanced, wantOK: true},
		{name: "web", value: "web", want: contentProfileWeb, wantOK: true},
		{name: "media", value: "media", want: contentProfileMedia, wantOK: true},
		{name: "realtime", value: "realtime", want: contentProfileRealtime, wantOK: true},
		{name: "mixed case", value: "MeDiA", want: contentProfileMedia, wantOK: true},
		{name: "surrounding whitespace", value: "  web  ", want: contentProfileWeb, wantOK: true},
		{name: "empty", value: ""},
		{name: "unknown", value: "corporate"},
		{name: "path traversal", value: "../../private"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseContentProfile(test.value)
			if ok != test.wantOK {
				t.Fatalf("parseContentProfile(%q) ok = %v, want %v", test.value, ok, test.wantOK)
			}
			if ok && got != test.want {
				t.Fatalf("parseContentProfile(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestResolveConfiguredProfile(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		env        string
		want       contentProfile
		wantError  bool
	}{
		{name: "nothing set defaults to balanced", want: contentProfileBalanced},
		{name: "blank env defaults to balanced", env: "   ", want: contentProfileBalanced},
		{name: "env selects profile", env: "media", want: contentProfileMedia},
		{name: "env is case insensitive", env: "ReAlTiMe", want: contentProfileRealtime},
		{name: "explicit value wins over env", configured: "web", env: "media", want: contentProfileWeb},
		{name: "invalid env rejected", env: "corporate", wantError: true},
		{name: "invalid explicit value rejected", configured: "corporate", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(ProfileEnvironment, test.env)

			got, err := resolveConfiguredProfile(test.configured)
			if (err != nil) != test.wantError {
				t.Fatalf("resolveConfiguredProfile() error = %v, wantError %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if got != test.want {
				t.Fatalf("resolveConfiguredProfile() = %q, want %q", got, test.want)
			}
		})
	}
}

// A browser reaching the node through a VLESS or Trojan fallback requests "/"
// with no query string, so the configured default is the only way an operator
// can decide which page that connection sees.
func TestHandlerServesConfiguredDefaultForBareRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		defaultProfile contentProfile
		path           string
		bodyText       string
	}{
		{name: "balanced", defaultProfile: contentProfileBalanced, path: "/", bodyText: "Today at a glance"},
		{name: "web", defaultProfile: contentProfileWeb, path: "/", bodyText: "Ideas for slower mornings"},
		{name: "media", defaultProfile: contentProfileMedia, path: "/", bodyText: "Continue listening"},
		{name: "realtime", defaultProfile: contentProfileRealtime, path: "/", bodyText: "Live rooms"},
		{
			name:           "explicit query overrides the default",
			defaultProfile: contentProfileWeb,
			path:           "/?profile=media",
			bodyText:       "Continue listening",
		},
		{
			name:           "unknown query falls back to the default, not balanced",
			defaultProfile: contentProfileRealtime,
			path:           "/?profile=corporate",
			bodyText:       "Live rooms",
		},
		{
			name:           "empty query falls back to the default",
			defaultProfile: contentProfileMedia,
			path:           "/?profile=",
			bodyText:       "Continue listening",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			newHandler(test.defaultProfile).ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if !strings.Contains(response.Body.String(), test.bodyText) {
				t.Fatalf("body does not contain %q", test.bodyText)
			}
		})
	}
}

func TestNewServerRejectsUnknownProfile(t *testing.T) {
	t.Setenv(ProfileEnvironment, "corporate")

	if _, err := NewServer(Config{ListenAddress: "127.0.0.1:60443"}); err == nil {
		t.Fatal("NewServer() error = nil, want an unknown profile error")
	}
}
