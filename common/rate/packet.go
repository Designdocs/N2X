package rate

import (
	"context"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// PacketConn holds at most the caller's one datagram while waiting. It never
// creates an unbounded queue and deliberately exposes no unwrap fast path.
type PacketConn struct {
	N.PacketConn
	limiter *Controller
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewPacketConnRateLimiter(conn N.PacketConn, limiter *Controller, parent context.Context) *PacketConn {
	ctx, cancel := context.WithCancel(parent)
	return &PacketConn{PacketConn: conn, limiter: limiter, ctx: ctx, cancel: cancel}
}

// Forward buffer requirements without giving the copy loop a way to bypass
// the limiter. Packet transports such as Snell prepend their wire header.
func (p *PacketConn) FrontHeadroom() int { return N.CalculateFrontHeadroom(p.PacketConn) }
func (p *PacketConn) RearHeadroom() int  { return N.CalculateRearHeadroom(p.PacketConn) }

func (p *PacketConn) Close() error { p.cancel(); return p.PacketConn.Close() }
func (p *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := p.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	n := int64(buffer.Len())
	if err = p.limiter.Wait(p.ctx, n); err != nil {
		return destination, err
	}
	p.limiter.Account(n)
	return destination, nil
}
func (p *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := int64(buffer.Len())
	if err := p.limiter.Wait(p.ctx, n); err != nil {
		buffer.Release()
		return err
	}
	err := p.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		p.limiter.Account(n)
	}
	return err
}
