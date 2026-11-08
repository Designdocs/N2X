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
	// Referenced file contents are part of the effective config, even when
	// their paths do not change.
	for _, core := range c.CoresConfig {
		if x := core.XrayConfig; x != nil {
			state.addFileData(x.RouteConfigPath, x.routeConfigData, nil)
			state.addFileData(x.OutboundConfigPath, x.outboundConfigData, nil)
			for _, path := range []string{x.DnsConfigPath, x.InboundConfigPath} {
				state.addFile(path)
			}
		}
		if s := core.SingConfig; s != nil {
			state.addFile(s.OriginalPath)
		}
	}
	return state, nil
}

// changedOutbounds returns the changed files only when all changes can be
// applied to the running outbound managers without rebuilding a core.
func (s watchState) changedOutbounds(next watchState, c *Conf, dnsPath string) map[string]struct{} {
	if s.retry || !bytes.Equal(s.config, next.config) || len(s.files) != len(next.files) {
		return nil
	}
	outbounds := make(map[string]struct{})
	for _, core := range c.CoresConfig {
		if x := core.XrayConfig; x != nil && x.OutboundConfigPath != "" {
			outbounds[x.OutboundConfigPath] = struct{}{}
		}
	}
	delete(outbounds, dnsPath)
	for _, core := range c.CoresConfig {
		if x := core.XrayConfig; x != nil {
			delete(outbounds, x.RouteConfigPath)
			delete(outbounds, x.DnsConfigPath)
			delete(outbounds, x.InboundConfigPath)
		}
		if sing := core.SingConfig; sing != nil {
			delete(outbounds, sing.OriginalPath)
		}
	}
	var changed map[string]struct{}
	for path, file := range next.files {
		previous, ok := s.files[path]
		if !ok {
			return nil
		}
		if previous.err == file.err && bytes.Equal(previous.data, file.data) {
			continue
		}
		if _, ok := outbounds[path]; !ok {
			return nil
		}
		if changed == nil {
			changed = make(map[string]struct{})
		}
		changed[path] = struct{}{}
	}
	return changed
}

func (s *watchState) addFile(path string) {
	if path == "" {
		return
	}
	if _, exists := s.files[path]; exists {
		return
	}
	data, err := os.ReadFile(path)
	s.addFileData(path, data, err)
}

func (s *watchState) addFileData(path string, data []byte, err error) {
	if path == "" {
		return
	}
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
