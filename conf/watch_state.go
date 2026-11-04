package conf

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/Designdocs/N2X/common/jsonutil"
)

// Keep a detached snapshot: starting a core may mutate its option structs.
// NodeConfig and CoreConfig hide their decoded options from JSON, so include
// those explicitly rather than marshaling Conf and losing their contents.
type watchState struct {
	config []byte
	files  map[string]watchFileState
	retry  bool
}

type watchFileState struct {
	data []byte
	err  string
}

func snapshotWatchState(c *Conf, dnsPath string) (watchState, error) {
	cores := make([]any, len(c.CoresConfig))
	for i, core := range c.CoresConfig {
		cores[i] = []any{core.Type, core.Name, core.XrayConfig, core.SingConfig}
	}
	nodes := make([]any, len(c.NodeConfig))
	for i, node := range c.NodeConfig {
		nodes[i] = []any{node.ApiConfig, node.Options}
	}
	raw, err := json.Marshal([]any{c.LogConfig, c.MemoryConfig, c.ScheduledRestart, cores, nodes})
	if err != nil {
		return watchState{}, err
	}
	config, err := jsonutil.Canonical(raw)
	if err != nil {
		return watchState{}, err
	}
	state := watchState{config: config, files: make(map[string]watchFileState)}
	state.addFile(dnsPath)
	// Re-saving the main file is also how operators apply changes to a
	// referenced route/outbound/original config. These contents are part of
	// the effective config, even when their path strings did not change.
	for _, core := range c.CoresConfig {
		if x := core.XrayConfig; x != nil {
			for _, path := range []string{x.DnsConfigPath, x.RouteConfigPath, x.InboundConfigPath, x.OutboundConfigPath} {
				state.addFile(path)
			}
		}
		if s := core.SingConfig; s != nil {
			state.addFile(s.OriginalPath)
		}
	}
	return state, nil
}

func (s *watchState) addFile(path string) {
	if path == "" {
		return
	}
	if _, exists := s.files[path]; exists {
		return
	}
	data, err := os.ReadFile(path)
	file := watchFileState{data: data}
	if err != nil {
		// Pre-existing DNS warnings are allowed; repairing the file still
		// has to count as a change.
		file.err = err.Error()
	} else if canonical, err := jsonutil.Canonical(data); err == nil {
		file.data = canonical
	}
	s.files[path] = file
}

func (s watchState) equal(other watchState) bool {
	if !bytes.Equal(s.config, other.config) || len(s.files) != len(other.files) {
		return false
	}
	for path, file := range s.files {
		otherFile, exists := other.files[path]
		if !exists || file.err != otherFile.err || !bytes.Equal(file.data, otherFile.data) {
			return false
		}
	}
	return true
}
