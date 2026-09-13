package node

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	log "github.com/sirupsen/logrus"
)

func TestNodeStartFailureDoesNotLeakPanelKey(t *testing.T) {
	const key = "node-secret-key-0123"
	limiter.Init()

	logger := log.StandardLogger()
	prevOut := logger.Out
	logs := &bytes.Buffer{}
	logger.SetOutput(logs)
	t.Cleanup(func() { logger.SetOutput(prevOut) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := "http://" + ln.Addr().String()
	ln.Close()

	nodes := []conf.NodeConfig{
		{ApiConfig: conf.ApiConfig{APIHost: host, Key: key, NodeType: "vless", NodeID: 3, Timeout: 2}},
	}
	n := New()
	failures, err := n.Start(nodes, &startStubCore{})
	defer n.Close()
	if err != nil {
		t.Fatalf("Start returned %v, want per-node failures only", err)
	}
	if len(failures) != 1 {
		t.Fatalf("failures = %+v, want exactly one", failures)
	}
	if msg := failures[0].Err.Error(); strings.Contains(msg, key) || !strings.Contains(msg, "token=[REDACTED]") {
		t.Errorf("failure error = %q, want the panel key masked", msg)
	}
	out := logs.String()
	if !strings.Contains(out, "Start node controller failed") {
		t.Fatalf("log = %q, want the start failure logged", out)
	}
	if strings.Contains(out, key) {
		t.Errorf("log leaks the panel key:\n%s", out)
	}
}
