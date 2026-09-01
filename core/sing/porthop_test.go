package sing

import (
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/porthop"
	"github.com/Designdocs/N2X/conf"
)

func TestHysteriaPortHopRangesPanelWins(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{ServerPorts: panel.PortRanges{"20000-21000"}}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{PortHopping: []string{"40000-41000"}}

	ranges, err := hysteriaPortHopRanges(info, options)
	if err != nil {
		t.Fatalf("hysteriaPortHopRanges: %v", err)
	}
	want := []porthop.Range{{From: 20000, To: 21000}}
	if len(ranges) != 1 || ranges[0] != want[0] {
		t.Fatalf("ranges = %v, want %v", ranges, want)
	}
}

func TestHysteriaPortHopRangesFallsBackToConfig(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{PortHopping: []string{"40000-41000"}}

	ranges, err := hysteriaPortHopRanges(info, options)
	if err != nil {
		t.Fatalf("hysteriaPortHopRanges: %v", err)
	}
	if len(ranges) != 1 || ranges[0] != (porthop.Range{From: 40000, To: 41000}) {
		t.Fatalf("ranges = %v", ranges)
	}
}

// Hysteria v1 hops the same way.
func TestHysteriaPortHopRangesHysteriaV1(t *testing.T) {
	info := testNode("hysteria", panel.Tls)
	info.Hysteria = &panel.HysteriaNode{ServerPorts: panel.PortRanges{"20000:21000"}}

	ranges, err := hysteriaPortHopRanges(info, testOptions())
	if err != nil {
		t.Fatalf("hysteriaPortHopRanges: %v", err)
	}
	if len(ranges) != 1 || ranges[0] != (porthop.Range{From: 20000, To: 21000}) {
		t.Fatalf("ranges = %v", ranges)
	}
}

func TestHysteriaPortHopRangesNoneConfigured(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{}

	ranges, err := hysteriaPortHopRanges(info, testOptions())
	if err != nil {
		t.Fatalf("hysteriaPortHopRanges: %v", err)
	}
	if len(ranges) != 0 {
		t.Fatalf("ranges = %v, want none", ranges)
	}
}

// Other protocols never redirect a range, whatever the local config says.
func TestHysteriaPortHopRangesIgnoresOtherProtocols(t *testing.T) {
	info := testNode("trojan", panel.Tls)
	info.Trojan = &panel.TrojanNode{}
	options := testOptions()
	options.SingOptions.HysteriaOptions = &conf.HysteriaOptions{PortHopping: []string{"40000-41000"}}

	ranges, err := hysteriaPortHopRanges(info, options)
	if err != nil {
		t.Fatalf("hysteriaPortHopRanges: %v", err)
	}
	if len(ranges) != 0 {
		t.Fatalf("ranges = %v, want none", ranges)
	}
}

func TestHysteriaPortHopRangesRejectsBadRange(t *testing.T) {
	info := testNode("hysteria2", panel.Tls)
	info.Hysteria2 = &panel.Hysteria2Node{ServerPorts: panel.PortRanges{"30000-20000"}}

	_, err := hysteriaPortHopRanges(info, testOptions())
	if err == nil {
		t.Fatal("hysteriaPortHopRanges returned no error for a reversed range")
	}
	if !strings.Contains(err.Error(), "30000-20000") {
		t.Fatalf("error %q does not name the bad range", err)
	}
}
