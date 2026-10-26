//go:build with_utls && race

package xray

import (
	"context"
	anytls "github.com/sagernet/sing-box/common/compat/anytls"
	"github.com/sagernet/sing-box/log"
	"net"
	"time"
)

// Normal wire tests use the independent public client. Race tests use the
// fixed client/session that the sing core runs, so its old client-only race
// cannot obscure server races. Both execute the same HTTPS/auth scenarios.
func createAnyTLSWireClient(ctx context.Context, password string, dial func(context.Context) (net.Conn, error)) (anyTLSWireClient, error) {
	return anytls.NewClient(ctx, anytls.ClientConfig{Password: password, DialOut: dial, Logger: log.NewNOPFactory().Logger(), IdleSessionCheckInterval: time.Second, IdleSessionTimeout: time.Second})
}
