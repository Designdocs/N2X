package porthop

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseRanges(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []Range
		wantErr bool
	}{
		{name: "dash", specs: []string{"20000-30000"}, want: []Range{{From: 20000, To: 30000}}},
		{name: "colon", specs: []string{"20000:30000"}, want: []Range{{From: 20000, To: 30000}}},
		{name: "single port", specs: []string{"8443"}, want: []Range{{From: 8443, To: 8443}}},
		{name: "several", specs: []string{"20000-21000", "30000"}, want: []Range{{From: 20000, To: 21000}, {From: 30000, To: 30000}}},
		{name: "spaces are trimmed", specs: []string{" 20000 - 30000 "}, want: []Range{{From: 20000, To: 30000}}},
		{name: "empty entries are skipped", specs: []string{"", "  ", "8443"}, want: []Range{{From: 8443, To: 8443}}},
		{name: "no ranges at all", specs: []string{"", " "}, want: nil},
		// A panel writes several ranges into one field, comma separated
		{name: "comma separated", specs: []string{"20000-21000,30000"}, want: []Range{{From: 20000, To: 21000}, {From: 30000, To: 30000}}},
		{name: "reversed", specs: []string{"30000-20000"}, wantErr: true},
		{name: "zero port", specs: []string{"0-100"}, wantErr: true},
		{name: "out of range", specs: []string{"20000-70000"}, wantErr: true},
		{name: "not a number", specs: []string{"http"}, wantErr: true},
		{name: "too many parts", specs: []string{"1-2-3"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRanges(tt.specs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRanges(%v) error = nil, want one", tt.specs)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRanges(%v) error = %v", tt.specs, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseRanges(%v) = %v, want %v", tt.specs, got, tt.want)
			}
		})
	}
}

// fakeRunner records every command instead of touching the host firewall.
type fakeRunner struct {
	calls   [][]string
	fail    func(name string, args []string) error
	missing map[string]bool
}

func (f *fakeRunner) run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail != nil {
		return f.fail(name, args)
	}
	return nil
}

func (f *fakeRunner) lookPath(name string) error {
	if f.missing[name] {
		return errors.New("not found")
	}
	return nil
}

func newTestManager(r *fakeRunner) *Manager {
	m := NewManager()
	m.goos = "linux"
	m.run = r.run
	m.lookPath = r.lookPath
	return m
}

func joined(calls [][]string) string {
	lines := make([]string, len(calls))
	for i, c := range calls {
		lines[i] = strings.Join(c, " ")
	}
	return strings.Join(lines, "\n")
}

func TestApplyRedirectsRangeToListenPort(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}}
	m := newTestManager(r)

	if err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	out := joined(r.calls)
	if !strings.Contains(out, "iptables -t nat -A PREROUTING -p udp --dport 20000:30000") {
		t.Fatalf("no redirect rule was added:\n%s", out)
	}
	if !strings.Contains(out, "-j REDIRECT --to-ports 8443") {
		t.Fatalf("rule does not redirect to the listen port:\n%s", out)
	}
	// The comment is what makes cleanup exact, so it must carry the node tag.
	if !strings.Contains(out, comment("hy2-1")) {
		t.Fatalf("rule carries no owner comment:\n%s", out)
	}
	// No ip6tables on this host: IPv6 is skipped rather than failing the node.
	if strings.Contains(out, ip6tablesCommand) {
		t.Fatalf("ip6tables was called although it is absent:\n%s", out)
	}
}

func TestApplyCoversIPv6WhenAvailable(t *testing.T) {
	r := &fakeRunner{}
	m := newTestManager(r)

	if err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !strings.Contains(joined(r.calls), ip6tablesCommand+" -t nat -A PREROUTING") {
		t.Fatalf("ipv6 rule missing:\n%s", joined(r.calls))
	}
}

// Applying twice must not stack duplicate rules: the stale ones are deleted
// first, so a node reload leaves the firewall exactly as it found it.
func TestApplyClearsStaleRulesFirst(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}}
	m := newTestManager(r)

	rule := Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}}
	if err := m.Apply(rule); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	r.calls = nil
	if err := m.Apply(rule); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}

	out := joined(r.calls)
	if !strings.Contains(out, "-D PREROUTING") {
		t.Fatalf("stale rule was not deleted before re-adding:\n%s", out)
	}
}

func TestApplyRollsBackOnFailure(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}}
	r.fail = func(name string, args []string) error {
		// Fail the second range only, after the first is already installed.
		for i, a := range args {
			if a == "--dport" && args[i+1] == "30000:31000" && args[0] == "-t" && contains(args, "-A") {
				return errors.New("iptables: permission denied")
			}
		}
		return nil
	}
	m := newTestManager(r)

	err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{
		{From: 20000, To: 21000},
		{From: 30000, To: 31000},
	}})
	if err == nil {
		t.Fatal("Apply() error = nil, want the iptables failure")
	}
	if !strings.Contains(joined(r.calls), "-D PREROUTING -p udp --dport 20000:21000") {
		t.Fatalf("the already installed rule was not rolled back:\n%s", joined(r.calls))
	}
	if m.Applied("hy2-1") {
		t.Fatal("a failed Apply must leave no state behind")
	}
}

func TestRemoveDeletesOnlyTheNodesRules(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}}
	m := newTestManager(r)

	if err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 21000}}}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := m.Apply(Redirect{Tag: "hy2-2", ListenPort: 9443, Ranges: []Range{{From: 30000, To: 31000}}}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	r.calls = nil

	if err := m.Remove("hy2-1"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	out := joined(r.calls)
	if !strings.Contains(out, "--dport 20000:21000") {
		t.Fatalf("the node's own rule was not deleted:\n%s", out)
	}
	if strings.Contains(out, "--dport 30000:31000") {
		t.Fatalf("another node's rule was deleted:\n%s", out)
	}
	if m.Applied("hy2-1") || !m.Applied("hy2-2") {
		t.Fatal("Remove() touched the wrong node's state")
	}
}

func TestRemoveAllClearsEveryNode(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}}
	m := newTestManager(r)

	for _, tag := range []string{"hy2-1", "hy2-2"} {
		if err := m.Apply(Redirect{Tag: tag, ListenPort: 8443, Ranges: []Range{{From: 20000, To: 21000}}}); err != nil {
			t.Fatalf("Apply(%s) error = %v", tag, err)
		}
	}
	if err := m.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
	if m.Applied("hy2-1") || m.Applied("hy2-2") {
		t.Fatal("RemoveAll() left state behind")
	}
}

// Port hopping is a Linux firewall feature; anywhere else the node must say so
// rather than come up quietly without the redirect.
func TestApplyRejectsNonLinuxHosts(t *testing.T) {
	r := &fakeRunner{}
	m := newTestManager(r)
	m.goos = "darwin"

	err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}})
	if err == nil {
		t.Fatal("Apply() error = nil, want an unsupported-platform error")
	}
	if len(r.calls) != 0 {
		t.Fatalf("commands were run on an unsupported platform: %v", r.calls)
	}
}

func TestApplyWithoutRangesIsANoop(t *testing.T) {
	r := &fakeRunner{}
	m := newTestManager(r)

	if err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("commands were run for an empty range set: %v", r.calls)
	}
	if m.Applied("hy2-1") {
		t.Fatal("an empty range set must not register state")
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
