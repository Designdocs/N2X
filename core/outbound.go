package core

import (
	"bytes"
	"fmt"

	"github.com/Designdocs/N2X/conf"
)

type outboundReloader interface {
	PrepareOutbounds(*conf.XrayConfig) (finish func(apply bool), err error)
}

func coreForConfig(running Core, config conf.CoreConfig) Core {
	if selector, ok := running.(*Selector); ok {
		name := config.Name
		if name == "" {
			name = config.Type
		}
		return selector.cores[name]
	}
	return running
}

// ReloadOutbounds prepares every affected core before publishing any of them.
func ReloadOutbounds(running Core, configs []conf.CoreConfig, changed map[string]struct{}) error {
	var prepared []func(bool)
	apply := false
	defer func() {
		for _, finish := range prepared {
			finish(apply)
		}
	}()
	for _, config := range configs {
		x := config.XrayConfig
		if x == nil {
			continue
		}
		if _, ok := changed[x.OutboundConfigPath]; !ok {
			continue
		}
		reloader, ok := coreForConfig(running, config).(outboundReloader)
		if !ok {
			return fmt.Errorf("%s: live outbound reload is unavailable for core %q", x.OutboundConfigPath, config.Name)
		}
		finish, err := reloader.PrepareOutbounds(x)
		if err != nil {
			return fmt.Errorf("%s: %w", x.OutboundConfigPath, err)
		}
		prepared = append(prepared, finish)
	}
	apply = true
	return nil
}

// CheckOutboundChanges also rejects broken outbound edits when a save of a
// different file requires the existing full reload path.
func CheckOutboundChanges(running Core, previous, next []conf.CoreConfig) error {
	previousFiles := make(map[string][]byte)
	for _, config := range previous {
		if x := config.XrayConfig; x != nil && x.OutboundConfigPath != "" {
			previousFiles[x.OutboundConfigPath], _ = x.ReadOutboundConfig()
		}
	}
	for _, config := range next {
		x := config.XrayConfig
		if x == nil || x.OutboundConfigPath == "" {
			continue
		}
		checker, ok := coreForConfig(running, config).(interface {
			CheckOutbounds(*conf.XrayConfig) error
		})
		if !ok {
			continue
		}
		data, err := x.ReadOutboundConfig()
		if err == nil && !bytes.Equal(previousFiles[x.OutboundConfigPath], data) {
			err = checker.CheckOutbounds(x)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", x.OutboundConfigPath, err)
		}
	}
	return nil
}
