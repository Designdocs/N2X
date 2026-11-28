package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Designdocs/N2X/common/domainusage"
	"github.com/Designdocs/N2X/conf"
)

func TestDomainUsageWireAndRateDuringPush(t *testing.T) {
	now := time.Now()
	store, err := domainusage.Open(filepath.Join(t.TempDir(), "usage.db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	f, release := store.Track(42, "example.com")
	defer release()
	var payload struct {
		Rows        []domainusage.Row
		Page, Pages int
		ID          string
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/push":
			f.Bytes.Add(9) // Arrived after the node captured the first billing interval.
			w.Header().Set("X-N2X-Domain-Rate", "2.5")
			w.Write([]byte("{}"))
		case "/api/v1/server/UniProxy/config":
			w.Header().Set("X-N2X-Domain-Rate", "0.5")
			w.Header().Set("X-N2X-Domain-Query", "c745d13e-b044-4418-a3b7-de0d918f769f,42,"+now.UTC().Format(time.DateOnly))
			w.WriteHeader(http.StatusNotModified)
		case "/api/v1/server/UniProxy/domainUsage":
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected call %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	c, err := New(&conf.ApiConfig{APIHost: ts.URL, NodeID: 1, NodeType: "vmess", Key: "local-test"})
	if err != nil {
		t.Fatal(err)
	}
	c.Domains.Store.Store(store)
	defer store.Close(now)
	f.Bytes.Add(100)
	if err = c.ReportUserTraffic([]UserTraffic{{UID: 42, Download: 100}}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	f.Bytes.Add(6)
	if err = store.Flush(now); err != nil {
		t.Fatal(err)
	}
	if err = c.AnswerDomainQuery(); err != nil {
		t.Fatal(err)
	}
	if payload.Pages != 1 || payload.Page != 0 || len(payload.Rows) != 1 || payload.Rows[0] != (domainusage.Row{Host: "example.com", Raw: 115, Weighted: 262, Connections: 1}) {
		t.Fatalf("%+v", payload)
	}
}

func TestDomainUsagePauseCancelsPagedReport(t *testing.T) {
	now := time.Now()
	store, err := domainusage.Open(filepath.Join(t.TempDir(), "usage.db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Pause()
	for i := 0; i <= domainusage.PageSize; i++ {
		_, release := store.Track(42, fmt.Sprintf("%03d.example", i))
		release()
	}
	if err := store.Flush(now); err != nil {
		t.Fatal(err)
	}
	first := make(chan struct{})
	unblock := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report struct {
			Page, Pages int
			Rows        []domainusage.Row
		}
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
			return
		}
		if report.Page != 0 || report.Pages != 2 || len(report.Rows) != domainusage.PageSize {
			t.Errorf("unexpected report %d/%d with %d rows", report.Page, report.Pages, len(report.Rows))
			return
		}
		close(first)
		select {
		case <-r.Context().Done():
		case <-unblock:
		}
	}))
	defer server.Close()
	defer close(unblock)
	client, err := New(&conf.ApiConfig{APIHost: server.URL, NodeID: 1, NodeType: "vmess", Key: "local-test"})
	if err != nil {
		t.Fatal(err)
	}
	client.Domains.Store.Store(store)
	client.Domains.query.Store(&DomainQuery{ID: "c745d13e-b044-4418-a3b7-de0d918f769f", UID: 42, Day: now})
	done := make(chan error, 1)
	go func() { done <- client.AnswerDomainQuery() }()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first page never arrived")
	}
	store.Pause()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("report continued after pause")
	}
}

func TestDomainUsageLiveQueryBeforeFirstHour(t *testing.T) {
	now := time.Now()
	store, err := domainusage.Open(filepath.Join(t.TempDir(), "usage.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Pause()
	f, stop := store.Track(42, "fresh.example")
	f.Bytes.Add(110)
	stop()
	var result struct {
		Rows  []domainusage.Row
		Until int64
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if r.Header.Get("X-N2X-Domain-Live") != "1" {
				t.Error("missing live capability")
			}
			w.Header().Set("X-N2X-Domain-Query", "c745d13e-b044-4418-a3b7-de0d918f769f,42,"+now.UTC().Format(time.DateOnly)+",live")
			w.WriteHeader(http.StatusNotModified)
		case "/api/v1/server/UniProxy/domainUsage":
			if e := json.NewDecoder(r.Body).Decode(&result); e != nil {
				t.Error(e)
			}
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	c, err := New(&conf.ApiConfig{APIHost: server.URL, NodeID: 1, NodeType: "vmess", Key: "local-test"})
	if err != nil {
		t.Fatal(err)
	}
	c.Domains.Store.Store(store)
	if _, err := c.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	if err := c.AnswerDomainQuery(); err != nil {
		t.Fatal(err)
	}
	if result.Until < now.Unix() || len(result.Rows) != 1 || result.Rows[0] != (domainusage.Row{Host: "fresh.example", Raw: 110, Weighted: 220, Connections: 1}) {
		t.Fatal(result)
	}
}

func TestDomainDayReportWire(t *testing.T) {
	now := time.Now().UTC()
	day := now.Truncate(24*time.Hour).AddDate(0, 0, -1)
	s, err := domainusage.Open(filepath.Join(t.TempDir(), "usage.db"), 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Pause()
	f, release := s.Track(42, "historical.test")
	f.Bytes.Add(17)
	release()
	if err = s.Flush(day.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f, release = s.Track(42, "current.test")
	f.Bytes.Add(100)
	release()
	requested := day
	var got struct {
		Rows  []domainusage.Row
		Until int64
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if r.Header.Get("X-N2X-Domain-Day") != "1" {
				t.Error("missing daily capability")
			}
			w.Header().Set("X-N2X-Domain-Query", "c745d13e-b044-4418-a3b7-de0d918f769f,42,"+requested.Format(time.DateOnly)+",day")
			w.WriteHeader(http.StatusNotModified)
		case "/api/v1/server/UniProxy/domainUsage":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
			}
			w.Write([]byte("{}"))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	c, err := New(&conf.ApiConfig{APIHost: ts.URL, NodeID: 1, NodeType: "vmess", Key: "local-test"})
	if err != nil {
		t.Fatal(err)
	}
	c.Domains.Store.Store(s)
	for _, delta := range []int{0, -1} {
		requested = day.AddDate(0, 0, delta)
		if _, err = c.GetNodeInfo(); err != nil {
			t.Fatal(err)
		}
		if err = c.AnswerDomainQuery(); err != nil {
			t.Fatal(err)
		}
		if delta == 0 && (got.Until == 0 || len(got.Rows) != 1 || got.Rows[0].Host != "historical.test" || got.Rows[0].Raw != 17 || got.Rows[0].Weighted != 51) {
			t.Fatal(got)
		}
		if delta < 0 && (got.Until != 0 || len(got.Rows) != 0) {
			t.Fatal(got)
		}
	}
}
