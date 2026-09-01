// Package porthop installs the firewall redirects that make Hysteria port
// hopping work.
//
// Port hopping is a client-side behaviour: the client keeps moving its source
// and destination port around inside a range so a censor cannot pin the flow
// to one UDP port. The server side has nothing to negotiate — it only has to
// answer on every port in that range. sing-box has no server-side option for
// this (server_ports/hop_interval exist on the outbound only), and binding a
// listener per port would cost one UDP socket per port, so the redirect is
// done where Hysteria's own documentation puts it: a nat PREROUTING rule that
// sends the whole range to the port the node actually listens on.
//
// Every rule carries a comment naming the node tag that owns it, which is what
// makes removal exact and a restart idempotent.
package porthop

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	iptablesCommand  = "iptables"
	ip6tablesCommand = "ip6tables"
	commentPrefix    = "N2X:porthop:"
)

// Range is an inclusive UDP port range.
type Range struct {
	From uint16
	To   uint16
}

func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(int(r.From))
	}
	// iptables spells a --dport range with a colon.
	return fmt.Sprintf("%d:%d", r.From, r.To)
}

// Redirect is the set of ranges one node wants pointed at its listen port.
type Redirect struct {
	Tag        string
	ListenPort uint16
	Ranges     []Range
}

// ParseRanges turns the panel's or the config's port range strings into
// ranges. "20000-30000", "20000:30000" and a bare "8443" are all accepted;
// empty entries are ignored so an operator can leave a placeholder behind.
//
// One entry may carry several comma-separated ranges, which is how a panel
// writes multiple ranges into its single port field.
func ParseRanges(specs []string) ([]Range, error) {
	var ranges []Range
	for _, entry := range specs {
		for _, spec := range strings.Split(entry, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			parts := strings.FieldsFunc(spec, func(r rune) bool { return r == '-' || r == ':' })
			if len(parts) == 0 || len(parts) > 2 {
				return nil, fmt.Errorf("port range %q is not a port or a port range", spec)
			}
			from, err := parsePort(parts[0])
			if err != nil {
				return nil, fmt.Errorf("port range %q: %w", spec, err)
			}
			to := from
			if len(parts) == 2 {
				if to, err = parsePort(parts[1]); err != nil {
					return nil, fmt.Errorf("port range %q: %w", spec, err)
				}
			}
			if to < from {
				return nil, fmt.Errorf("port range %q ends before it starts", spec)
			}
			ranges = append(ranges, Range{From: from, To: to})
		}
	}
	return ranges, nil
}

func parsePort(s string) (uint16, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number", strings.TrimSpace(s))
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is outside 1-65535", port)
	}
	return uint16(port), nil
}

// Manager owns the rules this process installed, so they can be taken back out
// when a node goes away or the process shuts down.
type Manager struct {
	mu      sync.Mutex
	applied map[string]Redirect

	// Injected for tests; the defaults talk to the host.
	goos     string
	run      func(name string, args ...string) error
	lookPath func(name string) error
}

func NewManager() *Manager {
	return &Manager{
		applied:  make(map[string]Redirect),
		goos:     runtime.GOOS,
		run:      runCommand,
		lookPath: lookPath,
	}
}

func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
	}
	return nil
}

func lookPath(name string) error {
	_, err := exec.LookPath(name)
	return err
}

// comment is the rule marker for a node. It is the only thing removal matches
// on, so it must stay stable across restarts.
func comment(tag string) string {
	return commentPrefix + tag
}

// Apply installs the redirect for one node, replacing anything this tag left
// behind earlier. A node with no ranges is a no-op, and a failure part-way
// through rolls back what it had already installed so the host is never left
// half configured.
func (m *Manager) Apply(r Redirect) error {
	if len(r.Ranges) == 0 {
		return nil
	}
	if m.goos != "linux" {
		return fmt.Errorf("hysteria port hopping needs nat PREROUTING rules and is only supported on linux, not %s", m.goos)
	}
	if err := m.lookPath(iptablesCommand); err != nil {
		return fmt.Errorf("hysteria port hopping needs the %s command: %w", iptablesCommand, err)
	}
	if r.ListenPort == 0 {
		return errors.New("hysteria port hopping needs the node listen port")
	}

	// A previous run of this node may still own rules; drop them so a reload
	// does not stack duplicates.
	m.remove(r.Tag)

	var installed []installedRule
	for _, command := range m.commands() {
		for _, portRange := range r.Ranges {
			if err := m.run(command, ruleArgs("-A", portRange, r.ListenPort, r.Tag)...); err != nil {
				m.rollback(installed, r)
				return fmt.Errorf("install port hopping rule for %s: %w", portRange, err)
			}
			installed = append(installed, installedRule{command: command, portRange: portRange})
		}
	}

	m.mu.Lock()
	m.applied[r.Tag] = r
	m.mu.Unlock()
	return nil
}

// Remove takes back the rules installed for one node. Removing a node that
// installed none is not an error.
func (m *Manager) Remove(tag string) error {
	return m.remove(tag)
}

// RemoveAll clears every rule this process installed. It is what shutdown
// calls, so a stopped N2X leaves no redirect behind.
func (m *Manager) RemoveAll() error {
	m.mu.Lock()
	tags := make([]string, 0, len(m.applied))
	for tag := range m.applied {
		tags = append(tags, tag)
	}
	m.mu.Unlock()
	sort.Strings(tags)

	var errs []error
	for _, tag := range tags {
		if err := m.remove(tag); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Applied reports whether this node currently owns firewall rules.
func (m *Manager) Applied(tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.applied[tag]
	return ok
}

func (m *Manager) remove(tag string) error {
	m.mu.Lock()
	r, ok := m.applied[tag]
	delete(m.applied, tag)
	m.mu.Unlock()
	if !ok {
		return nil
	}

	var errs []error
	for _, command := range m.commands() {
		for _, portRange := range r.Ranges {
			if err := m.run(command, ruleArgs("-D", portRange, r.ListenPort, tag)...); err != nil {
				errs = append(errs, fmt.Errorf("remove port hopping rule for %s: %w", portRange, err))
			}
		}
	}
	return errors.Join(errs...)
}

// installedRule is one rule an in-flight Apply already put in place.
type installedRule struct {
	command   string
	portRange Range
}

// rollback undoes rules installed during a failed Apply. Errors here are not
// worth reporting on top of the failure that caused the rollback.
func (m *Manager) rollback(installed []installedRule, r Redirect) {
	for i := len(installed) - 1; i >= 0; i-- {
		_ = m.run(installed[i].command, ruleArgs("-D", installed[i].portRange, r.ListenPort, r.Tag)...)
	}
}

// commands lists the firewall binaries to drive. IPv6 is included only when
// ip6tables exists: a host without it has no IPv6 nat table to configure, and
// failing the node over that would be wrong.
func (m *Manager) commands() []string {
	commands := []string{iptablesCommand}
	if err := m.lookPath(ip6tablesCommand); err == nil {
		commands = append(commands, ip6tablesCommand)
	}
	return commands
}

// ruleArgs builds one nat PREROUTING rule. The comment match must precede the
// jump target, which is also why rollback can rewrite argument 1 in place.
func ruleArgs(action string, portRange Range, listenPort uint16, tag string) []string {
	return []string{
		"-t", "nat",
		action, "PREROUTING",
		"-p", "udp",
		"--dport", portRange.String(),
		"-m", "comment", "--comment", comment(tag),
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(int(listenPort)),
	}
}
