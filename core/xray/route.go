package xray

import (
	"encoding/json/v2"
	"fmt"

	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildRouteConfig(c *conf.XrayConfig) (*router.Config, error) {
	data, err := c.ReadRouteConfig()
	if err != nil {
		return nil, err
	}
	var config coreConf.RouterConfig
	if data != nil {
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
	}
	for i, balancer := range config.Balancers {
		if balancer == nil {
			return nil, fmt.Errorf("balancers[%d] must be an object", i)
		}
	}
	return config.Build()
}

// CheckRouteConfig builds a candidate against the live Xray features without
// changing the router used by the running dispatcher.
func (c *Xray) CheckRouteConfig(config *conf.XrayConfig) (err error) {
	// Xray may panic while building a balancer with invalid dependencies.
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("build routing config: %v", value)
		}
	}()
	next, err := buildRouteConfig(config)
	if err != nil {
		return err
	}
	candidate, err := core.CreateObject(c.Server, next)
	if err != nil {
		return err
	}
	staged := candidate.(*router.Router)
	startErr := staged.Start()
	closeErr := staged.Close()
	if startErr != nil {
		return startErr
	}
	return closeErr
}
