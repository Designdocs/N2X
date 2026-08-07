package core

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
)

type Selector struct {
	cores map[string]Core
	nodes sync.Map
}

var _ RuntimeStatsProvider = (*Selector)(nil)

func NewSelector(c []conf.CoreConfig) (Core, error) {
	cs := make(map[string]Core, len(c))
	for _, t := range c {
		f, ok := cores[strings.ToLower(t.Type)]
		if !ok {
			return nil, errors.New("unknown core type: " + t.Type)
		}
		core1, err := f(&t)
		if err != nil {
			return nil, err
		}
		if t.Name == "" {
			cs[t.Type] = core1
		} else {
			cs[t.Name] = core1
		}
	}
	return &Selector{
		cores: cs,
	}, nil
}

func (s *Selector) Start() error {
	for i := range s.cores {
		err := s.cores[i].Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for i := range s.cores {
		if err := s.cores[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isSupported(protocol string, protocols []string) bool {
	for i := range protocols {
		if protocol == protocols[i] {
			return true
		}
	}
	return false
}

// corePriority ranks core types when a node does not pin one.
//
// Some protocols are served by more than one core on purpose — "anytls" has
// both an xray-native and a sing-box implementation — so the choice must not
// depend on Go's randomised map iteration order. Cores earlier in this list
// win, which keeps a deployment on the core it used before another core
// learned the same protocol. Pin a node explicitly with "Core" or "CoreName"
// to override.
var corePriority = []string{"xray", "sing"}

// orderedCoreNames returns the configured core names in a stable order:
// cores whose type appears in corePriority first, in that order, then the
// rest sorted by name.
func (s *Selector) orderedCoreNames() []string {
	names := make([]string, 0, len(s.cores))
	for name := range s.cores {
		names = append(names, name)
	}
	sort.Strings(names)

	rank := func(name string) int {
		coreType := s.cores[name].Type()
		for i, t := range corePriority {
			if t == coreType {
				return i
			}
		}
		return len(corePriority)
	}
	sort.SliceStable(names, func(i, j int) bool {
		return rank(names[i]) < rank(names[j])
	})
	return names
}

// selectCore resolves which configured core should serve a node.
func (s *Selector) selectCore(info *panel.NodeInfo, option *conf.Options) (Core, error) {
	if len(option.CoreName) > 0 {
		core, ok := s.cores[option.CoreName]
		if !ok {
			return nil, fmt.Errorf("no core named %q is configured", option.CoreName)
		}
		if !isSupported(info.Type, core.Protocols()) {
			return nil, fmt.Errorf("core %q does not support the %q node type", option.CoreName, info.Type)
		}
		return core, nil
	}

	names := s.orderedCoreNames()
	if len(option.Core) > 0 {
		for _, name := range names {
			core := s.cores[name]
			if core.Type() == option.Core && isSupported(info.Type, core.Protocols()) {
				return core, nil
			}
		}
		return nil, fmt.Errorf("no %q core supports the %q node type", option.Core, info.Type)
	}

	for _, name := range names {
		if core := s.cores[name]; isSupported(info.Type, core.Protocols()) {
			return core, nil
		}
	}
	return nil, fmt.Errorf("the %q node type is not supported by any configured core", info.Type)
}

func (s *Selector) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	core, err := s.selectCore(info, option)
	if err != nil {
		return err
	}
	if len(option.Core) == 0 {
		option.Core = core.Type()
		// Options carrying no Core were kept as raw JSON by conf; now that the
		// core is known, decode them into that core's option struct. A node
		// pinned by CoreName alone can reach here with nothing buffered, in
		// which case there is nothing left to decode.
		if len(option.RawOptions) > 0 {
			if err := option.UnmarshalJSON(option.RawOptions); err != nil {
				return fmt.Errorf("unmarshal option error: %s", err)
			}
			option.RawOptions = nil
		}
	}
	if err := core.AddNode(tag, info, option); err != nil {
		return err
	}
	s.nodes.Store(tag, core)
	return nil
}

func (s *Selector) DelNode(tag string) error {
	if t, e := s.nodes.Load(tag); e {
		err := t.(Core).DelNode(tag)
		if err != nil {
			return err
		}
		s.nodes.Delete(tag)
		return nil
	}
	return errors.New("the node is not have")
}

func (s *Selector) AddUsers(p *AddUsersParams) (added int, err error) {
	t, e := s.nodes.Load(p.Tag)
	if !e {
		return 0, errors.New("the node is not have")
	}
	return t.(Core).AddUsers(p)
}

func (s *Selector) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	return t.(Core).GetUserTrafficSlice(tag, reset)
}

// RuntimeStats forwards read-only protocol counters to the concrete core that
// owns the node. Multi-core deployments otherwise hide optional capabilities
// implemented by an individual core behind the Selector wrapper.
func (s *Selector) RuntimeStats(tag string) RuntimeStats {
	core, ok := s.nodes.Load(tag)
	if !ok {
		return RuntimeStats{}
	}
	provider, ok := core.(RuntimeStatsProvider)
	if !ok {
		return RuntimeStats{}
	}
	return provider.RuntimeStats(tag)
}

func (s *Selector) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	t, e := s.nodes.Load(tag)
	if !e {
		return errors.New("the node is not have")
	}
	return t.(Core).DelUsers(users, tag, info)
}

func (s *Selector) Protocols() []string {
	protocols := make([]string, 0)
	for i := range s.cores {
		protocols = append(protocols, s.cores[i].Protocols()...)
	}
	return protocols
}

func (s *Selector) Type() string {
	t := "Selector("
	var flag bool
	for n, c := range s.cores {
		if flag {
			t += " "
		} else {
			flag = true
		}
		if len(n) == 0 {
			t += c.Type()
		} else {
			t += n
		}
	}
	t += ")"
	return t
}
