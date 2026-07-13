package decoy

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var forbiddenResponseStrings = []string{
	"N2X",
	"ArtX",
	"AnyTLS",
	"proxy",
}

func TestValidateListenAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "IPv4 loopback", address: "127.0.0.1:60443"},
		{name: "IPv6 loopback", address: "[::1]:60443"},
		{name: "wildcard", address: "0.0.0.0:60443", wantErr: true},
		{name: "public address", address: "192.0.2.1:60443", wantErr: true},
		{name: "hostname", address: "localhost:60443", wantErr: true},
		{name: "missing port", address: "127.0.0.1", wantErr: true},
		{name: "zero port", address: "127.0.0.1:0", wantErr: true},
		{name: "large port", address: "127.0.0.1:65536", wantErr: true},
		{name: "non-numeric port", address: "127.0.0.1:https", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateListenAddress(test.address)
			if test.wantErr && err == nil {
				t.Fatalf("ValidateListenAddress(%q) returned nil", test.address)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("ValidateListenAddress(%q): %v", test.address, err)
			}
		})
	}
}

func TestDecoyHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method      string
		path        string
		status      int
		contentType string
		bodyText    string
	}{
		{method: http.MethodGet, path: "/", status: http.StatusOK, contentType: "text/html", bodyText: "Today at a glance"},
		{method: http.MethodHead, path: "/", status: http.StatusOK, contentType: "text/html"},
		{method: http.MethodGet, path: "/assets/site.css", status: http.StatusOK, contentType: "text/css", bodyText: "#121415"},
		{method: http.MethodHead, path: "/assets/site.css", status: http.StatusOK, contentType: "text/css"},
		{method: http.MethodGet, path: "/robots.txt", status: http.StatusOK, contentType: "text/plain", bodyText: "Disallow"},
		{method: http.MethodHead, path: "/robots.txt", status: http.StatusOK, contentType: "text/plain"},
		{method: http.MethodGet, path: "/favicon.ico", status: http.StatusNoContent},
		{method: http.MethodHead, path: "/favicon.ico", status: http.StatusNoContent},
		{method: http.MethodGet, path: "/missing", status: http.StatusNotFound, contentType: "text/plain", bodyText: "Not Found"},
		{method: http.MethodHead, path: "/missing", status: http.StatusNotFound, contentType: "text/plain"},
	}

	handler := newHandler()
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			result := response.Result()
			defer result.Body.Close()
			body, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			if result.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", result.StatusCode, test.status)
			}
			if test.contentType != "" && !strings.HasPrefix(result.Header.Get("Content-Type"), test.contentType) {
				t.Fatalf("Content-Type = %q, want prefix %q", result.Header.Get("Content-Type"), test.contentType)
			}
			if test.method == http.MethodHead && len(body) != 0 {
				t.Fatalf("HEAD body = %q, want empty", body)
			}
			if test.bodyText != "" && !strings.Contains(string(body), test.bodyText) {
				t.Fatalf("body does not contain %q", test.bodyText)
			}

			serializedHeaders := make([]string, 0, len(result.Header))
			for name, values := range result.Header {
				serializedHeaders = append(serializedHeaders, name+":"+strings.Join(values, ","))
			}
			responseText := string(body) + "\n" + strings.Join(serializedHeaders, "\n")
			for _, forbidden := range forbiddenResponseStrings {
				if strings.Contains(responseText, forbidden) {
					t.Fatalf("response contains forbidden string %q", forbidden)
				}
			}
		})
	}
}

func TestDecoyHandlerSelectsPageByContentProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		bodyText string
	}{
		{name: "balanced default", path: "/", bodyText: "Today at a glance"},
		{name: "balanced explicit", path: "/?profile=balanced", bodyText: "Today at a glance"},
		{name: "web", path: "/?profile=web", bodyText: "Ideas for slower mornings"},
		{name: "media", path: "/?profile=media", bodyText: "Continue listening"},
		{name: "realtime", path: "/?profile=realtime", bodyText: "Live rooms"},
		{name: "normalized", path: "/?profile=%20MeDiA%20", bodyText: "Continue listening"},
		{name: "unknown", path: "/?profile=../../private", bodyText: "Today at a glance"},
	}

	handler := newHandler()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if !strings.Contains(response.Body.String(), test.bodyText) {
				t.Fatalf("body does not contain %q", test.bodyText)
			}
		})
	}
}

func TestDecoyHandlerRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("data"))
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestEmbeddedPageUsesStaticSemanticMarkup(t *testing.T) {
	t.Parallel()

	var markup strings.Builder
	for _, profile := range []string{"balanced", "web", "media", "realtime"} {
		html, err := fs.ReadFile(embeddedAssets, "assets/"+profile+".html")
		if err != nil {
			t.Fatalf("read %s page: %v", profile, err)
		}
		pageMarkup := string(html)
		markup.WriteString(pageMarkup)
		for _, element := range []string{"<main", "<section", "<header", "<footer"} {
			if !strings.Contains(pageMarkup, element) {
				t.Fatalf("%s page does not contain semantic element %q", profile, element)
			}
		}
		if !strings.Contains(pageMarkup, `href="/assets/site.css"`) {
			t.Fatalf("%s page does not link the embedded stylesheet", profile)
		}
		for _, forbidden := range []string{"<script", "style="} {
			if strings.Contains(strings.ToLower(pageMarkup), forbidden) {
				t.Fatalf("%s page contains forbidden markup %q", profile, forbidden)
			}
		}
	}

	css, err := fs.ReadFile(embeddedAssets, "assets/site.css")
	if err != nil {
		t.Fatalf("read stylesheet: %v", err)
	}
	if !strings.Contains(string(css), "#121415") {
		t.Fatal("stylesheet does not contain the required dark background")
	}

	assetText := strings.ToLower(markup.String() + "\n" + string(css))
	for _, forbidden := range []string{"n2x", "artx", "anytls", "proxy"} {
		if strings.Contains(assetText, forbidden) {
			t.Fatalf("embedded assets contain forbidden string %q", forbidden)
		}
	}
}
