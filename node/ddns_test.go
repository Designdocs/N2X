package node

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Designdocs/N2X/conf"
)

type testDDNSUpdater struct {
	calls  atomic.Int32
	closed atomic.Bool
}

type retryDDNSUpdater struct {
	calls chan int
	count int
}

func (u *retryDDNSUpdater) Update(context.Context) error {
	u.count++
	u.calls <- u.count
	if u.count == 1 {
		return errors.New("temporary provider failure")
	}
	return nil
}

func TestDDNSPeriodicLoopRetriesAfterFailureAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := &retryDDNSUpdater{calls: make(chan int, 10)}
	done := make(chan struct{})
	go func() { runDDNS(ctx, ddnsTestNode().Options.DDNSConfig, u, 5*time.Millisecond); close(done) }()
	for i := 1; i <= 3; i++ {
		select {
		case got := <-u.calls:
			if got != i {
				t.Fatalf("unexpected retry count %d", got)
			}
		case <-time.After(time.Second):
			t.Fatal("DDNS stopped retrying after a failure")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DDNS did not stop on cancellation")
	}
}

func (u *testDDNSUpdater) Update(context.Context) error { u.calls.Add(1); return nil }
func (u *testDDNSUpdater) Close()                       { u.closed.Store(true) }

func ddnsTestNode() conf.NodeConfig {
	return conf.NodeConfig{Options: conf.Options{DDNSConfig: conf.DDNSConfig{
		Enabled: true, Provider: "cloudflare", Domain: "edge.example.com", DNSEnv: map[string]string{"CF_DNS_API_TOKEN": "token"},
	}}}
}

func TestDDNSWorkersDisabledDeduplicatedAndStopped(t *testing.T) {
	u := &testDDNSUpdater{}
	n := New()
	n.newDDNSUpdater = func(conf.DDNSConfig) (ddnsUpdater, error) { return u, nil }
	ctx, cancel := context.WithCancel(context.Background())
	n.retryCancel = cancel
	disabled := ddnsTestNode()
	disabled.Options.DDNSConfig.Enabled = false
	if err := n.startDDNS(ctx, []conf.NodeConfig{disabled}); err != nil {
		t.Fatal(err)
	}
	if u.calls.Load() != 0 {
		t.Fatal("disabled DDNS ran")
	}
	if err := n.startDDNS(ctx, []conf.NodeConfig{ddnsTestNode(), ddnsTestNode()}); err != nil {
		t.Fatal(err)
	}
	if u.calls.Load() != 1 {
		t.Fatal("identical record configs were not deduplicated")
	}
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not stop DDNS")
	}
	if !u.closed.Load() {
		t.Fatal("DDNS network resources were not closed")
	}
}

func TestDDNSValidatesAllWorkersBeforeFirstWrite(t *testing.T) {
	u := &testDDNSUpdater{}
	n := New()
	n.newDDNSUpdater = func(conf.DDNSConfig) (ddnsUpdater, error) { return u, nil }
	invalid := ddnsTestNode()
	invalid.Options.DDNSConfig.Domain = "*.example.com"
	if err := n.startDDNS(context.Background(), []conf.NodeConfig{ddnsTestNode(), invalid}); err == nil {
		t.Fatal("invalid DDNS config accepted")
	}
	if u.calls.Load() != 0 {
		t.Fatal("DNS modified before configuration validation finished")
	}
}

func TestNodeDDNSStartsBeforePanelAndSurvivesPanelFailure(t *testing.T) {
	u := &testDDNSUpdater{}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u.calls.Load() == 0 {
			t.Error("panel bootstrap preceded initial DDNS sync")
		}
		http.NotFound(w, r)
	}))
	defer panel.Close()
	n := New()
	n.newDDNSUpdater = func(conf.DDNSConfig) (ddnsUpdater, error) { return u, nil }
	node := ddnsTestNode()
	node.ApiConfig = conf.ApiConfig{APIHost: panel.URL, Key: "test-key", NodeID: 1, NodeType: "anytls"}
	failures, err := n.Start([]conf.NodeConfig{node}, &startStubCore{})
	defer n.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].Stage != StagePanel {
		t.Fatalf("expected panel failure, got %+v", failures)
	}
	if u.calls.Load() != 1 || u.closed.Load() {
		t.Fatal("DDNS worker stopped after panel failure")
	}
}
