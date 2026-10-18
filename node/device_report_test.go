package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

type deviceTrafficCore struct {
	vCore.Core
	traffic []panel.UserTraffic
}

func (core *deviceTrafficCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return core.traffic, nil
}

func newDeviceReportController(t *testing.T, receive http.HandlerFunc) *Controller {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alive" {
			w.Write([]byte(`{}`))
			return
		}
		receive(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := panel.New(&conf.ApiConfig{APIHost: server.URL, Key: "test-token", NodeID: 1, NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	l := limiter.AddLimiter(t.Name(), &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "uuid-1"}}, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(t.Name()) })
	return &Controller{server: &deviceTrafficCore{}, apiClient: client, tag: t.Name(), limiter: l, Options: &conf.Options{}}
}

func TestDeviceReportsKeepLiveIPAndClearClosedIP(t *testing.T) {
	var reports []map[int][]string
	var mu sync.Mutex
	c := newDeviceReportController(t, func(w http.ResponseWriter, r *http.Request) {
		var data map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		mu.Lock()
		reports = append(reports, data)
		mu.Unlock()
		w.Write([]byte(`{}`))
	})
	close := c.limiter.TrackConnection(format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
	for range 2 {
		if err := c.reportUserTrafficTask(); err != nil {
			t.Fatal(err)
		}
	}
	close()
	for range 2 {
		if err := c.reportUserTrafficTask(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 4 {
		t.Fatalf("reports = %d, want 4 including offline and empty snapshots", len(reports))
	}
	for _, report := range reports[:2] {
		if len(report[1]) != 1 || report[1][0] != "192.0.2.1" {
			t.Fatalf("idle live connection was lost: %v", report)
		}
	}
	if ips, ok := reports[2][1]; !ok || ips == nil || len(ips) != 0 {
		t.Fatalf("closed user needs an explicit empty IP list for HTTP cleanup: %v", reports[2])
	}
	if reports[3] == nil || len(reports[3]) != 0 {
		t.Fatalf("final snapshot must be an empty object: %v", reports[3])
	}
}

func TestFailedOfflineDeviceReportIsRetried(t *testing.T) {
	var fail atomic.Bool
	var offlineReports atomic.Int32
	c := newDeviceReportController(t, func(w http.ResponseWriter, r *http.Request) {
		var data map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		if ips, ok := data[1]; ok && ips != nil && len(ips) == 0 {
			offlineReports.Add(1)
		}
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.Write([]byte(`{}`))
	})
	close := c.limiter.TrackConnection(format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	close()
	fail.Store(true)
	c.reportUserTrafficTask()
	fail.Store(false)
	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	if got := offlineReports.Load(); got < 2 {
		t.Fatalf("offline cleanup was not retried: %d reports", got)
	}
}

func TestTrafficThresholdDoesNotDropAnEstablishedDevice(t *testing.T) {
	reports := make(chan map[int][]string, 3)
	c := newDeviceReportController(t, func(w http.ResponseWriter, r *http.Request) {
		var data map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		reports <- data
		w.Write([]byte(`{}`))
	})
	c.Options.DeviceOnlineMinTraffic = 100
	close := c.limiter.TrackConnection(format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
	defer close()
	core := c.server.(*deviceTrafficCore)
	for _, traffic := range []int64{1, 200000, 1} {
		core.traffic = []panel.UserTraffic{{UID: 1, Upload: traffic}}
		if err := c.reportUserTrafficTask(); err != nil {
			t.Fatal(err)
		}
	}
	if first := <-reports; len(first) != 0 {
		t.Fatalf("new low-traffic connection bypassed the configured threshold: %v", first)
	}
	for range 2 {
		if report := <-reports; len(report[1]) != 1 {
			t.Fatalf("established connection disappeared below the traffic threshold: %v", report)
		}
	}
}

func TestUnacknowledgedOnlineReportStillClearsClosedUser(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	reports := make(chan map[int][]string, 2)
	c := newDeviceReportController(t, func(w http.ResponseWriter, r *http.Request) {
		var data map[int][]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		reports <- data
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.Write([]byte(`{}`))
	})
	close := c.limiter.TrackConnection(format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
	c.reportUserTrafficTask()
	close()
	fail.Store(false)
	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	<-reports
	if report := <-reports; report[1] == nil || len(report[1]) != 0 {
		t.Fatalf("ambiguous online write was not explicitly cleared: %v", report)
	}
}

func TestDeviceReportsAreSafeDuringTaskOverlap(t *testing.T) {
	var received atomic.Int32
	c := newDeviceReportController(t, func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Write([]byte(`{}`))
	})
	close := c.limiter.TrackConnection(format.UserTag(t.Name(), "uuid-1"), "192.0.2.1")
	defer close()
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if err := c.reportUserTrafficTask(); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if got := received.Load(); got != 8 {
		t.Fatalf("overlapping tasks sent %d reports, want 8", got)
	}
}
