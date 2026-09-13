package panel

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
	"github.com/sirupsen/logrus"
)

const secretKey = "panel-secret-key-0123"

// captureLog sends the standard logrus logger to a buffer for the rest of
// the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	logger := logrus.StandardLogger()
	prevOut, prevLevel := logger.Out, logger.GetLevel()
	buf := &bytes.Buffer{}
	logger.SetOutput(buf)
	logger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		logger.SetOutput(prevOut)
		logger.SetLevel(prevLevel)
	})
	return buf
}

// unreachableHost returns a base URL nothing listens on.
func unreachableHost(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

func newRedactTestClient(t *testing.T, host string) *Client {
	t.Helper()
	c, err := New(&conf.ApiConfig{
		APIHost:  host,
		Key:      secretKey,
		NodeType: "vless",
		NodeID:   3,
		Timeout:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRedactToken(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "token between params",
			in:   `Get "http://h/p?node_id=3&token=abc&node_type=vless": dial tcp`,
			want: `Get "http://h/p?node_id=3&token=[REDACTED]&node_type=vless": dial tcp`,
		},
		{
			name: "token last before quote",
			in:   `Get "http://h/p?node_id=3&token=abc": EOF`,
			want: `Get "http://h/p?node_id=3&token=[REDACTED]": EOF`,
		},
		{
			name: "escaped token",
			in:   "http://h/p?token=a%2Bb%3D c",
			want: "http://h/p?token=[REDACTED] c",
		},
		{
			name: "no token",
			in:   "request failed: empty response",
			want: "request failed: empty response",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactToken(tt.in); got != tt.want {
				t.Errorf("RedactToken(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTransportErrorsDoNotLeakToken(t *testing.T) {
	logs := captureLog(t)
	c := newRedactTestClient(t, unreachableHost(t))

	calls := map[string]func() error{
		"GetNodeInfo": func() error {
			_, err := c.GetNodeInfo()
			return err
		},
		"ReportUserTraffic": func() error {
			return c.ReportUserTraffic([]UserTraffic{{UID: 1, Upload: 1, Download: 1}})
		},
		"ReportNodeStatus": func() error {
			return c.ReportNodeStatus(&NodeStatus{})
		},
	}
	for name, call := range calls {
		err := call()
		if err == nil {
			t.Fatalf("%s: want an error from an unreachable panel", name)
		}
		if strings.Contains(err.Error(), secretKey) {
			t.Errorf("%s error leaks the panel key: %v", name, err)
		}
		if !strings.Contains(err.Error(), "token=[REDACTED]") {
			t.Errorf("%s error = %v, want the request URL with a masked token", name, err)
		}
	}

	out := logs.String()
	if strings.Contains(out, secretKey) {
		t.Errorf("log leaks the panel key:\n%s", out)
	}
	// resty's retry warnings go through logrus now, not straight to stderr.
	if !strings.Contains(out, "Attempt") || !strings.Contains(out, "token=[REDACTED]") {
		t.Errorf("log = %q, want resty retry warnings with a masked token", out)
	}
}

func TestErrorStatusBodyDoesNotLeakToken(t *testing.T) {
	logs := captureLog(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Some panels echo the full request URL in their error page.
		http.Error(w, "forbidden: "+r.URL.String(), http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := newRedactTestClient(t, server.URL)

	_, err := c.GetNodeInfo()
	if err == nil {
		t.Fatal("want an error for a 403 response")
	}
	if strings.Contains(err.Error(), secretKey) {
		t.Errorf("error leaks the panel key: %v", err)
	}
	if !strings.Contains(err.Error(), "token=[REDACTED]") {
		t.Errorf("error = %v, want the echoed URL with a masked token", err)
	}
	if strings.Contains(logs.String(), secretKey) {
		t.Errorf("log leaks the panel key:\n%s", logs.String())
	}
}
