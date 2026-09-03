package node

import (
	"context"
	"errors"
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
	pressure []vCore.ArtXHostPressureSample
	budgets  []vCore.ArtXWindowBudgetPolicy
	// budgetErr is what ConfigureArtXWindowBudget reports back, standing in
	// for the core rejecting an out-of-range percentage.
	budgetErr error
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

func (core *artXFlowControlCore) ObserveArtXHostPressure(sample vCore.ArtXHostPressureSample) {
	core.mu.Lock()
	defer core.mu.Unlock()
	core.pressure = append(core.pressure, sample)
}

func (core *artXFlowControlCore) ConfigureArtXWindowBudget(policy vCore.ArtXWindowBudgetPolicy) error {
	core.mu.Lock()
	defer core.mu.Unlock()
	core.budgets = append(core.budgets, policy)
	return core.budgetErr
}

// observedBudgets returns the policies the core was handed, and how many
// pressure samples had already arrived when the first one landed. The budget
// has to be installed before any probe, so the first configure must precede
// every observation.
func (core *artXFlowControlCore) observedBudgets() ([]vCore.ArtXWindowBudgetPolicy, int) {
	core.mu.Lock()
	defer core.mu.Unlock()
	return core.budgets, len(core.pressure)
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
	observed := make(chan vCore.ArtXHostPressureSample, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	probe := vCore.ArtXHostPressureSample{
		CPUPercent:           42.5,
		MemoryPercent:        61.25,
		MemoryTotalBytes:     1004535808,
		MemoryAvailableBytes: 402653184,
	}
	go func() {
		defer close(done)
		runArtXPressureSampler(ctx, time.Millisecond,
			func() (vCore.ArtXHostPressureSample, bool) { return probe, true },
			func(sample vCore.ArtXHostPressureSample) {
				select {
				case observed <- sample:
				default:
				}
			})
	}()

	// The absolute memory sizes must survive the hop as well: they are what
	// the core's per-connection window budget is computed from.
	if sample := <-observed; sample != probe {
		t.Fatalf("observed = %+v, want %+v", sample, probe)
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
			func() (vCore.ArtXHostPressureSample, bool) {
				select {
				case probes <- struct{}{}:
				default:
				}
				return vCore.ArtXHostPressureSample{}, false
			},
			func(vCore.ArtXHostPressureSample) { observations++ })
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

func TestSampleHostPressureReportsAbsoluteMemorySizes(t *testing.T) {
	sample, ok := sampleHostPressure()
	if !ok {
		t.Skip("no host utilisation probe succeeded in this environment")
	}
	// gopsutil reports memory on every platform this agent builds for, so a
	// usable sample must carry sizes the window budget can divide up. Zero
	// would silently disable the clamp everywhere.
	if sample.MemoryTotalBytes == 0 {
		t.Fatal("MemoryTotalBytes = 0, want the host memory size")
	}
	if sample.MemoryAvailableBytes == 0 {
		t.Fatal("MemoryAvailableBytes = 0, want the available memory size")
	}
	if sample.MemoryAvailableBytes > sample.MemoryTotalBytes {
		t.Fatalf("available %d exceeds total %d", sample.MemoryAvailableBytes, sample.MemoryTotalBytes)
	}
	if sample.MemoryPercent < 0 || sample.MemoryPercent > 100 {
		t.Fatalf("MemoryPercent = %v, want [0, 100]", sample.MemoryPercent)
	}
	if sample.CPUPercent < 0 || sample.CPUPercent > 100 {
		t.Fatalf("CPUPercent = %v, want [0, 100]", sample.CPUPercent)
	}
}

func TestStartArtXPressureSamplerConfiguresTheWindowBudget(t *testing.T) {
	wireNode := func() *panel.NodeInfo {
		return &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{
			Underlay:    "artx-wire",
			FlowControl: panel.ArtXFlowControlAuto,
		}}
	}
	tests := []struct {
		name    string
		options *conf.Options
		want    vCore.ArtXWindowBudgetPolicy
	}{
		{
			name:    "absent block takes the core default",
			options: &conf.Options{},
			want:    vCore.ArtXWindowBudgetPolicy{},
		},
		{
			name: "configured block is forwarded verbatim",
			options: &conf.Options{ArtXOptions: &conf.ArtXOptions{
				WindowBudgetSharePercent:   40,
				WindowBudgetReservePercent: 15,
			}},
			want: vCore.ArtXWindowBudgetPolicy{SharePercent: 40, ReservePercent: 15},
		},
		{
			name: "a zero field is forwarded as zero, i.e. the core default",
			options: &conf.Options{ArtXOptions: &conf.ArtXOptions{
				WindowBudgetSharePercent: 40,
			}},
			want: vCore.ArtXWindowBudgetPolicy{SharePercent: 40},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &artXFlowControlCore{}
			controller := &Controller{
				server:  server,
				tag:     "artx-canary",
				info:    wireNode(),
				Options: test.options,
			}

			controller.startArtXPressureSampler(controller.info)
			t.Cleanup(controller.stopArtXPressureSampler)

			budgets, samples := server.observedBudgets()
			if len(budgets) != 1 {
				t.Fatalf("configure calls = %d, want exactly 1", len(budgets))
			}
			if budgets[0] != test.want {
				t.Fatalf("policy = %+v, want %+v", budgets[0], test.want)
			}
			if samples != 0 {
				t.Fatalf("%d pressure samples arrived before the budget was configured", samples)
			}
		})
	}
}

func TestStartArtXPressureSamplerSurvivesARejectedBudget(t *testing.T) {
	// A rejected percentage is logged and dropped: the core keeps a usable
	// default, so the sampler must still come up.
	server := &artXFlowControlCore{budgetErr: errors.New("share percent 200 is above 100")}
	controller := &Controller{
		server: server,
		tag:    "artx-canary",
		info: &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{
			Underlay:    "artx-wire",
			FlowControl: panel.ArtXFlowControlAuto,
		}},
		Options: &conf.Options{ArtXOptions: &conf.ArtXOptions{WindowBudgetSharePercent: 200}},
	}

	controller.startArtXPressureSampler(controller.info)
	t.Cleanup(controller.stopArtXPressureSampler)

	if controller.artXPressureCancel == nil {
		t.Fatal("a rejected budget value stopped the sampler from starting")
	}
}

func TestArtXPressureSamplerNotConfiguredForNonWireNodes(t *testing.T) {
	server := &artXFlowControlCore{}
	controller := &Controller{
		server:  server,
		tag:     "artx-canary",
		info:    &panel.NodeInfo{Type: "artx", ArtX: &panel.ArtXNode{Underlay: "anytls"}},
		Options: &conf.Options{ArtXOptions: &conf.ArtXOptions{WindowBudgetSharePercent: 40}},
	}

	controller.startArtXPressureSampler(controller.info)

	if budgets, _ := server.observedBudgets(); len(budgets) != 0 {
		t.Fatalf("non-wire node configured the window budget: %+v", budgets)
	}
}
