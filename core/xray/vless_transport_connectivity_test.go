//go:build with_utls

package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
)

func TestXrayVLESSTransportsHTTPSAndAccounting(t *testing.T) {
	for _, tc := range []struct{ name, network, flow, key, settings string }{
		{"TCP-TLS", "tcp", "", "", "{}"},
		{"TCP-TLS-Vision", "tcp", "xtls-rprx-vision", "", "{}"},
		{"WS-TLS", "ws", "", "wsSettings", `{"path":"/wire-test"}`},
		{"gRPC-TLS", "grpc", "", "grpcSettings", `{"serviceName":"wire-test"}`},
		{"gRPC-multi-TLS", "grpc", "", "grpcSettings", `{"serviceName":"wire-test","multiMode":true}`},
		{"HTTPUpgrade-TLS", "httpupgrade", "", "httpupgradeSettings", `{"path":"/wire-test"}`},
		{"XHTTP-packet-up-TLS", "xhttp", "", "xhttpSettings", `{"path":"/wire-test","mode":"packet-up"}`},
		{"XHTTP-stream-one-TLS", "xhttp", "", "xhttpSettings", `{"path":"/wire-test","mode":"stream-one"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProtocolFixture(t, &panel.NodeInfo{Type: "vless", Security: panel.Tls, VAllss: &panel.VAllssNode{Tls: panel.Tls, Network: tc.network, Flow: tc.flow, NetworkSettings: json.RawMessage(tc.settings)}})
			host, p, err := net.SplitHostPort(f.address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(p)
			if err != nil {
				t.Fatal(err)
			}
			stream := map[string]any{"network": tc.network, "security": "tls", "tlsSettings": map[string]any{"serverName": "127.0.0.1", "disableSystemRoot": true, "certificates": []any{map[string]any{"certificate": []string{string(f.certPEM)}, "usage": "verify"}}}}
			if tc.key != "" {
				stream[tc.key] = json.RawMessage(tc.settings)
			}
			raw, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"id": f.users[0].Uuid, "encryption": "none", "flow": tc.flow}}}}}, "streamSettings": stream}}})
			if err != nil {
				t.Fatal(err)
			}
			var cfg xconf.Config
			if err = json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.LogConfig = &xconf.LogConfig{LogLevel: "debug"}
			built, err := cfg.Build()
			if err != nil {
				t.Fatal(err)
			}
			client, err := xcore.New(built)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			dest, err := xnet.ParseDestination("tcp:" + f.target)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 3 {
				conn, err := xcore.Dial(ctx, client, dest)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.https(ctx, conn); err != nil {
					t.Fatal(fmt.Errorf("request %d: %w", i, err))
				}
			}
			f.checkTraffic(t, 101, int64(3*len(f.payload)))
		})
	}
}
