package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
)

func TestArtXUserRateBytesPerSecondMatchesLimiterConversion(t *testing.T) {
	// limiter/limiter.go converts the panel's Mbps figure with
	// `limit * 1000000 / 8`; the auto policy has to agree with the bucket
	// that actually shapes the user or it will size windows for a rate the
	// user can never reach.
	cases := []struct {
		name      string
		nodeLimit int
		userLimit int
		want      uint64
	}{
		{name: "unlimited", nodeLimit: 0, userLimit: 0, want: 0},
		{name: "user only", nodeLimit: 0, userLimit: 100, want: 12500000},
		{name: "node only", nodeLimit: 50, userLimit: 0, want: 6250000},
		{name: "node is tighter", nodeLimit: 20, userLimit: 100, want: 2500000},
		{name: "user is tighter", nodeLimit: 100, userLimit: 20, want: 2500000},
		{name: "negative is unlimited", nodeLimit: -1, userLimit: -3, want: 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := artXUserRateBytesPerSecond(testCase.nodeLimit, testCase.userLimit); got != testCase.want {
				t.Fatalf("artXUserRateBytesPerSecond(%d, %d) = %d, want %d",
					testCase.nodeLimit, testCase.userLimit, got, testCase.want)
			}
		})
	}
}

func TestBuildArtXUserRatesKeysMatchXrayUserEmails(t *testing.T) {
	const tag = "[panel]-artx:7"
	users := []panel.UserInfo{
		{Id: 1, Uuid: "uuid-one", SpeedLimit: 100},
		{Id: 2, Uuid: "uuid-two"},
	}

	rates := buildArtXUserRates(tag, 0, users)

	// core/xray/artxwire.go builds every ArtX user's Email with
	// format.UserTag(tag, uuid); the lookup key has to be byte-identical.
	if got, ok := rates[format.UserTag(tag, "uuid-one")]; !ok || got != 12500000 {
		t.Fatalf("rate for uuid-one = %d (present=%v), want 12500000", got, ok)
	}
	if got, ok := rates[format.UserTag(tag, "uuid-two")]; !ok || got != 0 {
		t.Fatalf("rate for uuid-two = %d (present=%v), want 0", got, ok)
	}
	if len(rates) != 2 {
		t.Fatalf("rates = %#v, want exactly two entries", rates)
	}
}

type artXFlowControlCore struct {
	vCore.Core
	mu       sync.Mutex
	rates    map[string]map[string]uint64
	cleared  []string
	pressure [][2]float64
}

func (core *artXFlowControlCore) SetArtXUserRates(tag string, rates map[string]uint64) {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.rates == nil {
		core.rates = make(map[string]map[string]uint64)
	}
	core.rates[tag] = rates
}

func (core *artXFlowControlCore) ClearArtXUserRates(tag string) {
	core.mu.Lock()
	defer core.mu.Unlock()
	core.cleared = append(core.cleared, tag)
}

func (core *artXFlowControlCore) ObserveArtXHostPressure(cpuPercent, memoryPercent float64) {
	core.mu.Lock()
	defer core.mu.Unlock()
	core.pressure = append(core.pressure, [2]float64{cpuPercent, memoryPercent})
}

func TestPublishArtXUserRatesSkipsNonWireNodes(t *testing.T) {
	server := &artXFlowControlCore{}
	controller := &Controller{
		server:   server,
		tag:      "artx-canary",
		userList: []panel.UserInfo{{Id: 1, Uuid: "uuid-one", SpeedLimit: 100}},
		info:     &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{Underlay: "anytls"}},
		Options:  &conf.Options{},
	}

	controller.publishArtXUserRates()

	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.rates) != 0 {
		t.Fatalf("non-wire node published rates: %#v", server.rates)
	}
}

func TestPublishArtXUserRatesSendsWireNodeTable(t *testing.T) {
	server := &artXFlowControlCore{}
	controller := &Controller{
		server:   server,
		tag:      "artx-canary",
		userList: []panel.UserInfo{{Id: 1, Uuid: "uuid-one", SpeedLimit: 100}},
		info: &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{
			Underlay:    "artx-wire",
			FlowControl: panel.ArtXFlowControlAuto,
		}},
		Options: &conf.Options{},
	}

	controller.publishArtXUserRates()

	server.mu.Lock()
	defer server.mu.Unlock()
	rates := server.rates["artx-canary"]
	if got := rates[format.UserTag("artx-canary", "uuid-one")]; got != 12500000 {
		t.Fatalf("published rate = %d, want 12500000 (table %#v)", got, rates)
	}
}

func TestClearArtXUserRatesReleasesTheTag(t *testing.T) {
	server := &artXFlowControlCore{}
	controller := &Controller{
		server: server,
		tag:    "artx-canary",
		info: &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{
			Underlay: "artx-wire",
		}},
		Options: &conf.Options{},
	}

	controller.clearArtXUserRates()

	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.cleared) != 1 || server.cleared[0] != "artx-canary" {
		t.Fatalf("cleared = %#v, want [artx-canary]", server.cleared)
	}
}

func TestRunArtXPressureSamplerObservesUntilCancelled(t *testing.T) {
	observed := make(chan [2]float64, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		runArtXPressureSampler(ctx, time.Millisecond,
			func() (float64, float64, bool) { return 42.5, 61.25, true },
			func(cpuPercent, memoryPercent float64) {
				select {
				case observed <- [2]float64{cpuPercent, memoryPercent}:
				default:
				}
			})
	}()

	sample := <-observed
	if sample[0] != 42.5 || sample[1] != 61.25 {
		t.Fatalf("observed = %v, want [42.5 61.25]", sample)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sampler did not stop on context cancellation")
	}
}

func TestRunArtXPressureSamplerSkipsFailedProbes(t *testing.T) {
	var observations int
	ctx, cancel := context.WithCancel(context.Background())
	probes := make(chan struct{}, 4)
	done := make(chan struct{})

	go func() {
		defer close(done)
		runArtXPressureSampler(ctx, time.Millisecond,
			func() (float64, float64, bool) {
				select {
				case probes <- struct{}{}:
				default:
				}
				return 0, 0, false
			},
			func(float64, float64) { observations++ })
	}()

	<-probes
	<-probes
	cancel()
	<-done

	if observations != 0 {
		t.Fatalf("observations = %d, want 0 when the probe fails", observations)
	}
}

func TestArtXPressureSamplerLifecycleIsIdempotent(t *testing.T) {
	server := &artXFlowControlCore{}
	controller := &Controller{
		server: server,
		tag:    "artx-canary",
		info: &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{
			Underlay:    "artx-wire",
			FlowControl: panel.ArtXFlowControlAuto,
		}},
		Options: &conf.Options{},
	}

	controller.startArtXPressureSampler(controller.info)
	first := controller.artXPressureCancel
	controller.startArtXPressureSampler(controller.info)
	if controller.artXPressureCancel == nil {
		t.Fatal("sampler was not started")
	}
	if first == nil {
		t.Fatal("first start did not record a cancel function")
	}

	controller.stopArtXPressureSampler()
	if controller.artXPressureCancel != nil {
		t.Fatal("stop did not clear the cancel function")
	}
	// A second stop must not panic.
	controller.stopArtXPressureSampler()
}

func TestArtXPressureSamplerNotStartedForNonWireNodes(t *testing.T) {
	controller := &Controller{
		server:  &artXFlowControlCore{},
		tag:     "artx-canary",
		info:    &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{Underlay: "anytls"}},
		Options: &conf.Options{},
	}

	controller.startArtXPressureSampler(controller.info)

	if controller.artXPressureCancel != nil {
		t.Fatal("non-wire node started a pressure sampler")
	}
}
