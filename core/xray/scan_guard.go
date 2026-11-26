package xray

import (
	"context"
	"github.com/Designdocs/N2X/common/scanguard"
	"github.com/Designdocs/N2X/conf"
	"github.com/xtls/xray-core/transport/internet"
	"io"
	"net"
)

var wrapScanListener = scanguard.WrapVisitorListener

func withWSScanGuard(ctx context.Context, cfg conf.WSScanGuardConfig) context.Context {
	if scanguard.HasRelayCA(cfg) || (cfg.Enabled && len(cfg.DirectOnlyNodes) > 0) {
		wrap := wrapScanListener
		ctx = internet.WithInboundListenerWrapper(ctx, func(tag string, l net.Listener) (net.Listener, error) {
			return wrap(tag, cfg, l)
		})
	}
	if !cfg.Enabled {
		return ctx
	}
	ctx = internet.WithSensitivePathFilter(ctx, func(tag string) internet.WrongPathFilter { return scanguard.SensitiveFilter(tag, cfg) })
	ctx = internet.WithRejectedStreamFilter(ctx, func(tag string, conn net.Conn, prefix []byte, rest io.Reader) bool {
		return scanguard.RejectedStream(tag, cfg, conn, prefix, rest)
	})
	return internet.WithWrongPathFilter(ctx, func(tag string) internet.WrongPathFilter { return scanguard.Filter(tag, cfg) })
}
