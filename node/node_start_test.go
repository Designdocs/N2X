package node

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

// startStubCore accepts every node removal and fails every node addition
// with addErr.
type startStubCore struct {
	vCore.Core
	addErr error
}

func (c *startStubCore) AddNode(string, *panel.NodeInfo, *conf.Options) error { return c.addErr }

func (c *startStubCore) DelNode(string) error { return nil }

// fakePanel serves a node whose config body is nodeBody, one user
// and an empty alive list. A nil nodeBody answers the config request with 404.
func fakePanel(t *testing.T, nodeBody *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if nodeBody == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(*nodeBody))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func nodeBody(fields string) *string {
	body := `{"server_port": 443, "base_config": {"push_interval": 60, "pull_interval": 60}, ` + fields + `}`
	return &body
}

func TestNodeStartReportsWhichStageFailed(t *testing.T) {
	limiter.Init()
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name     string
		nodeType string
		nodeBody *string
		addErr   error
		want     StartStage
		wantText string
	}{
		{
			name:     "panel unreachable",
			nodeType: "anytls",
			nodeBody: nil,
			want:     StagePanel,
			wantText: "get node info error",
		},
		{
			name:     "certificate file missing",
			nodeType: "anytls",
			nodeBody: nodeBody(`"server_name": "edge.example.com", "cert_config": {"cert_mode": "file", "cert_file": "` +
				missing + `.pem", "key_file": "` + missing + `.key"}`),
			want:     StageCert,
			wantText: "cert file not found",
		},
		{
			name:     "core rejects the node",
			nodeType: "shadowsocks",
			nodeBody: nodeBody(`"cipher": "aes-128-gcm"`),
			addErr:   errors.New("inbound build failed"),
			want:     StageCore,
			wantText: "inbound build failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			panelServer := fakePanel(t, tt.nodeBody)
			nodes := []conf.NodeConfig{
				{ApiConfig: conf.ApiConfig{APIHost: panelServer.URL, Key: "token", NodeType: tt.nodeType, NodeID: 7}},
			}
			n := New()
			failures, err := n.Start(nodes, &startStubCore{addErr: tt.addErr})
			defer n.Close()
			if err != nil {
				t.Fatalf("Start returned %v, want per-node failures only", err)
			}
			if len(failures) != 1 {
				t.Fatalf("failures = %+v, want exactly one", failures)
			}
			got := failures[0]
			if got.Index != 0 || got.Stage != tt.want {
				t.Errorf("failure = {Index:%d Stage:%q}, want {Index:0 Stage:%q}", got.Index, got.Stage, tt.want)
			}
			if got.Err == nil || !strings.Contains(got.Err.Error(), tt.wantText) {
				t.Errorf("failure error = %v, want it to mention %q", got.Err, tt.wantText)
			}
		})
	}
}
