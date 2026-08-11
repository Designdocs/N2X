package xray

import (
	"context"
	"errors"
	"fmt"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
)

type DNSConfig struct {
	Servers []interface{} `json:"servers"`
	Tag     string        `json:"tag"`
}

func (c *Xray) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	c.nodeReportMinTrafficBytes[tag] = config.ReportMinTraffic * 1024
	err := updateDNSConfig(info)
	if err != nil {
		return fmt.Errorf("build dns error: %s", err)
	}
	inboundConfig, err := buildInbound(config, info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = c.addInbound(inboundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	outBoundConfig, err := buildOutbound(config, tag)
	if err != nil {
		return fmt.Errorf("build outbound error: %s", err)
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {
		_ = c.removeInbound(tag)
		return fmt.Errorf("add outbound error: %s", err)
	}
	if err := c.startNativeUDP(tag, info, config); err != nil {
		return errors.Join(
			fmt.Errorf("start native UDP error: %w", err),
			wrapRollbackError("remove outbound", c.removeOutbound(tag)),
			wrapRollbackError("remove inbound", c.removeInbound(tag)),
		)
	}
	return nil
}

func (c *Xray) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ihm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Xray) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ohm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Xray) DelNode(tag string) error {
	return errors.Join(
		wrapRollbackError("stop native UDP", c.stopNativeUDP(tag)),
		wrapRollbackError("remove inbound", c.removeInbound(tag)),
		wrapRollbackError("remove outbound", c.removeOutbound(tag)),
	)
}

func wrapRollbackError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (c *Xray) removeInbound(tag string) error {
	return c.ihm.RemoveHandler(context.Background(), tag)
}

func (c *Xray) removeOutbound(tag string) error {
	err := c.ohm.RemoveHandler(context.Background(), tag)
	return err
}
