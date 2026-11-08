package core

import (
	"bytes"
	"fmt"

	"github.com/Designdocs/N2X/conf"
)

type routeConfigChecker interface {
	CheckRouteConfig(*conf.XrayConfig) error
}

// CheckRouteChanges checks edited route files before the server closes cores.
func CheckRouteChanges(running Core, previous, next []conf.CoreConfig) error {
	checker, ok := running.(routeConfigChecker)
	if selector, selected := running.(*Selector); selected {
		for _, name := range selector.orderedCoreNames() {
			if checker, ok = selector.cores[name].(routeConfigChecker); ok {
				break
			}
		}
	}
	if !ok {
		return nil
	}
	oldRoutes := make(map[string][]byte)
	for _, core := range previous {
		if x := core.XrayConfig; x != nil {
			oldRoutes[x.RouteConfigPath], _ = x.ReadRouteConfig()
		}
	}
	for _, core := range next {
		x := core.XrayConfig
		if x == nil || x.RouteConfigPath == "" {
			continue
		}
		data, err := x.ReadRouteConfig()
		if err == nil && !bytes.Equal(oldRoutes[x.RouteConfigPath], data) {
			err = checker.CheckRouteConfig(x)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", x.RouteConfigPath, err)
		}
	}
	return nil
}
