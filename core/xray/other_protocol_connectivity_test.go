package xray

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXrayOtherCommonProtocolsWithIndependentClients(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
		tls            bool
	}{
		{"VMess-AEAD", "vmess", false}, {"VMess-AEAD-TLS", "vmess", true}, {"Trojan-TLS", "trojan", true}, {"Shadowsocks-AES128GCM", "shadowsocks", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &panel.NodeInfo{Type: tc.protocol}
			if tc.tls {
				info.Security = panel.Tls
			}
			switch tc.protocol {
			case "vmess":
				info.VAllss = &panel.VAllssNode{Network: "tcp", Tls: info.Security}
			case "trojan":
				info.Trojan = &panel.TrojanNode{Network: "tcp", Tls: info.Security}
			case "shadowsocks":
				info.Shadowsocks = &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
			}
			f := newProtocolFixture(t, info)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			for i := range 3 {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.address)
				if err != nil {
					t.Fatal(err)
				}
				raw.SetDeadline(time.Now().Add(10 * time.Second))
				t.Cleanup(func() { raw.Close() })
				if tc.tls {
					secure := tls.Client(raw, &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1"})
					if err = secure.HandshakeContext(ctx); err != nil {
						t.Fatal(err)
					}
					raw = secure
				}
				var conn net.Conn
				switch tc.protocol {
				case "vmess":
					client, err := vmess.NewClient(f.users[0].Uuid, "aes-128-gcm", 0)
					if err != nil {
						t.Fatal(err)
					}
					conn, err = client.DialConn(raw, M.ParseSocksaddr(f.target))
					if err != nil {
						t.Fatal(err)
					}
				case "shadowsocks":
					client, err := shadowaead.New("aes-128-gcm", nil, f.users[0].Uuid)
					if err != nil {
						t.Fatal(err)
					}
					conn, err = client.DialConn(raw, M.ParseSocksaddr(f.target))
					if err != nil {
						t.Fatal(err)
					}
				case "trojan":
					sum := sha256.Sum224([]byte(f.users[0].Uuid))
					if _, err = fmt.Fprintf(raw, "%s\r\n%c", hex.EncodeToString(sum[:]), 1); err != nil {
						t.Fatal(err)
					}
					if err = M.SocksaddrSerializer.WriteAddrPort(raw, M.ParseSocksaddr(f.target)); err != nil {
						t.Fatal(err)
					}
					if _, err = raw.Write([]byte("\r\n")); err != nil {
						t.Fatal(err)
					}
					conn = raw
				}
				if err := f.https(ctx, conn); err != nil {
					t.Fatalf("HTTPS request %d: %v", i, err)
				}
			}
			f.checkTraffic(t, 101, int64(3*len(f.payload)))
		})
	}
}
