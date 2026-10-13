package dispatcher

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

type bufferPolicyManager struct {
	policy.DefaultManager
	level uint32
}

func (p *bufferPolicyManager) ForLevel(level uint32) policy.Session {
	p.level = level
	return policy.Session{Buffer: policy.Buffer{PerConnection: 64 * 1024}}
}

func TestAnyTLSLinksUseTheUserBufferLimit(t *testing.T) {
	for _, name := range []string{"anytls", "vless"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := new(bufferPolicyManager)
				d := &DefaultDispatcher{policy: manager}
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
					Name: name,
					User: &protocol.MemoryUser{Level: 7},
				})
				ctx = policy.ContextWithBufferPolicy(ctx, policy.Buffer{PerConnection: 512 * 1024})
				inbound, outbound, _, err := d.getLink(ctx, net.Network_TCP)
				if err != nil {
					t.Fatal(err)
				}
				defer common.Interrupt(inbound.Reader)
				defer common.Interrupt(outbound.Reader)
				for _, direction := range []*transport.Link{
					{Reader: outbound.Reader, Writer: inbound.Writer},
					{Reader: inbound.Reader, Writer: outbound.Writer},
				} {
					queued := make(buf.MultiBuffer, 0, 33)
					for range 33 {
						b := buf.New()
						b.Extend(buf.Size)
						queued = append(queued, b)
					}
					if err := direction.Writer.WriteMultiBuffer(queued); err != nil {
						t.Fatal(err)
					}
					written := make(chan error, 1)
					go func() {
						b := buf.New()
						b.Extend(buf.Size)
						written <- direction.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
					}()
					synctest.Wait()
					if name == "anytls" {
						select {
						case err := <-written:
							t.Fatalf("write exceeded the configured buffer limit: %v", err)
						default:
						}
					} else if err := <-written; err != nil {
						t.Fatal(err)
					}
					data, err := direction.Reader.ReadMultiBuffer()
					buf.ReleaseMulti(data)
					if err != nil {
						t.Fatal(err)
					}
					if name == "anytls" {
						if err := <-written; err != nil {
							t.Fatal(err)
						}
					}
				}
				if name == "anytls" && manager.level != 7 {
					t.Fatalf("policy level = %d, want 7", manager.level)
				}
			})
		})
	}
}
