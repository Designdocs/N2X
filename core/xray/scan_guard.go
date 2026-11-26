package xray

import (
	"context"
	"github.com/Designdocs/N2X/common/scanguard"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/transport/internet"
)

func withWSScanGuard(ctx context.Context, cfg conf.WSScanGuardConfig) context.Context {
	if !cfg.Enabled {
		return ctx
	}
	return internet.WithWrongPathFilter(ctx, func(tag string) internet.WrongPathFilter { return scanguard.Filter(tag, cfg) })
}
