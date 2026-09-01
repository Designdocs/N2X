package porthop

import (
	"errors"
	"fmt"
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
	// listing is what "iptables -S PREROUTING" reports, per command.
	listing   map[string]string
	listFails bool
}

func (f *fakeRunner) run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail != nil {
		return f.fail(name, args)
	}
	return nil
}

func (f *fakeRunner) output(name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.listFails {
		return "", errors.New("iptables: permission denied")
	}
	return f.listing[name], nil
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
	m.output = r.output
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
	tag := "hy2-1"
	r := &fakeRunner{
		missing: map[string]bool{ip6tablesCommand: true},
		listing: map[string]string{
			iptablesCommand: listedRule(tag, "20000:30000", 8443),
		},
	}
	m := newTestManager(r)

	rule := Redirect{Tag: tag, ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}}
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

// listedRule renders one rule the way "iptables -t nat -S PREROUTING" prints
// it, comment quoting included.
func listedRule(tag, dport string, listenPort int) string {
	return fmt.Sprintf(
		`-A PREROUTING -p udp -m udp --dport %s -m comment --comment %q -j REDIRECT --to-ports %d`,
		dport, comment(tag), listenPort)
}

// The rules an earlier run left behind are the whole reason the chain is read
// back: this process installed nothing, so only the listing can find them.
func TestApplyRemovesRulesLeftByAnEarlierRun(t *testing.T) {
	tag := "[https://panel.example.com]-hysteria2:12"
	r := &fakeRunner{
		missing: map[string]bool{ip6tablesCommand: true},
		listing: map[string]string{
			iptablesCommand: strings.Join([]string{
				// Someone else's redirect, and a hand written one with no
				// comment: neither may be touched.
				`-A PREROUTING -p udp -m udp --dport 20000:30000 -j REDIRECT --to-ports 10443`,
				listedRule("[https://panel.example.com]-hysteria2:99", "40000:41000", 9443),
				// Two copies of our own rule, from two unclean restarts.
				listedRule(tag, "20000:30000", 10443),
				listedRule(tag, "20000:30000", 10443),
			}, "\n"),
		},
	}
	m := newTestManager(r)

	if err := m.Apply(Redirect{Tag: tag, ListenPort: 10443, Ranges: []Range{{From: 20000, To: 30000}}}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var deletes int
	for _, call := range r.calls {
		if contains(call, "-D") {
			deletes++
			if !contains(call, comment(tag)) {
				t.Fatalf("a rule that is not ours was deleted: %v", call)
			}
		}
	}
	// One delete per listed copy: iptables removes a single rule per -D.
	if deletes != 2 {
		t.Fatalf("deleted %d leftover rules, want 2:\n%s", deletes, joined(r.calls))
	}
	if !strings.Contains(joined(r.calls), "-t nat -A PREROUTING") {
		t.Fatalf("the redirect was not installed after the cleanup:\n%s", joined(r.calls))
	}
}

// A chain that cannot even be read means the node cannot be sure its redirect
// is the only one, so it says so instead of adding a rule on top.
func TestApplyFailsWhenTheChainCannotBeRead(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{ip6tablesCommand: true}, listFails: true}
	m := newTestManager(r)

	err := m.Apply(Redirect{Tag: "hy2-1", ListenPort: 8443, Ranges: []Range{{From: 20000, To: 30000}}})
	if err == nil {
		t.Fatal("Apply() error = nil, want the listing failure")
	}
	if strings.Contains(joined(r.calls), "-A PREROUTING") {
		t.Fatalf("a rule was installed although the chain was unreadable:\n%s", joined(r.calls))
	}
}

func TestStaleRulesMatchesOnlyTheTagsOwnRules(t *testing.T) {
	tag := "hy2-1"
	listing := strings.Join([]string{
		"-P PREROUTING ACCEPT",
		`-A PREROUTING -p udp -m udp --dport 20000:30000 -j REDIRECT --to-ports 8443`,
		listedRule("hy2-2", "40000:41000", 9443),
		listedRule(tag, "20000:30000", 8443),
	}, "\n")

	rules := staleRules(listing, comment(tag))
	if len(rules) != 1 {
		t.Fatalf("staleRules() = %v, want exactly the tag's own rule", rules)
	}
	want := []string{"-p", "udp", "-m", "udp", "--dport", "20000:30000", "-m", "comment", "--comment", comment(tag), "-j", "REDIRECT", "--to-ports", "8443"}
	if !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("staleRules() = %v, want %v", rules[0], want)
	}
}

// A node tag carries the panel URL in brackets, so iptables prints the comment
// quoted; splitting on spaces alone would never match it back.
func TestTokenizeRuleKeepsQuotedComments(t *testing.T) {
	tag := "[https://panel.example.com]-hysteria2:12"
	tokens := tokenizeRule(listedRule(tag, "20000:30000", 10443))

	var found bool
	for i, token := range tokens {
		if token == "--comment" {
			found = tokens[i+1] == comment(tag)
		}
	}
	if !found {
		t.Fatalf("the quoted comment did not survive tokenizing: %v", tokens)
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
