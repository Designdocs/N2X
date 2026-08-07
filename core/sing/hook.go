package sing

import (
	"context"
	"net"
	"sync"

	"github.com/Designdocs/N2X/common/counter"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/common/rate"
	"github.com/Designdocs/N2X/limiter"
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*HookServer)(nil)

// HookServer sits between sing-box's router and the outbound handler. Every
// routed connection passes through it so the node's speed/device limits and
// routing rules are enforced, and so the bytes are accounted against the user.
type HookServer struct {
	counter sync.Map // node tag -> *counter.TrafficCounter

	// resolveTag maps a sing-box inbound tag to the panel node tag that owns
	// it. They differ for composite protocols: a ShadowTLS node is served by
	// a public shadowtls inbound plus an internal shadowsocks detour, and the
	// router rewrites the inbound tag to the detour before the connection
	// reaches us. Limits and traffic must still be attributed to the node.
	resolveTag func(inboundTag string) string
}

func newHookServer() *HookServer {
	return &HookServer{
		resolveTag: func(tag string) string { return tag },
	}
}

func (h *HookServer) ModeList() []string {
	return nil
}

// checkAccess resolves the owning node, applies its limits and routing rules,
// and reports whether the connection may proceed. The returned bucket is the
// user's speed-limit token bucket, and is only meaningful for streams.
func (h *HookServer) checkAccess(m *adapter.InboundContext, isTCP bool) (nodeTag string, bucket *ratelimit.Bucket, ok bool) {
	nodeTag = h.resolveTag(m.Inbound)
	l, err := limiter.GetLimiter(nodeTag)
	if err != nil {
		// No limiter registered for the node: let the traffic through rather
		// than dropping every connection on a transient registration gap.
		log.Warn("get limiter for ", nodeTag, " error: ", err)
		return nodeTag, nil, true
	}

	taguuid := format.UserTag(nodeTag, m.User)
	ip := m.Source.Addr.String()
	bucket, reject := l.CheckLimit(taguuid, ip, isTCP, isTCP)
	if reject {
		log.Error("[", nodeTag, "] Limited ", m.User, " by ip or conn")
		return nodeTag, nil, false
	}

	if destination := m.Destination.AddrString(); l.CheckDomainRule(destination) {
		log.Error("User ", m.User, " access domain ", destination, " reject by rule")
		return nodeTag, nil, false
	}
	if len(m.Protocol) != 0 && l.CheckProtocolRule(m.Protocol) {
		log.Error("User ", m.User, " access protocol ", m.Protocol, " reject by rule")
		return nodeTag, nil, false
	}
	return nodeTag, bucket, true
}

func (h *HookServer) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	nodeTag, bucket, ok := h.checkAccess(&m, true)
	if !ok {
		conn.Close()
		return conn
	}
	if bucket != nil {
		conn = rate.NewConnRateLimiter(conn, bucket)
	}
	return counter.NewConnCounter(conn, h.storageFor(nodeTag, m.User))
}

func (h *HookServer) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	// The datagram path enforces device/connection limits only: the token
	// bucket in common/rate wraps net.Conn and has no packet equivalent, so
	// speed limits apply to the stream side.
	nodeTag, _, ok := h.checkAccess(&m, false)
	if !ok {
		conn.Close()
		return conn
	}
	return counter.NewPacketConnCounter(conn, h.storageFor(nodeTag, m.User))
}

// storageFor returns the per-user traffic storage for a node, creating the
// node's counter on first use.
func (h *HookServer) storageFor(nodeTag, user string) *counter.TrafficStorage {
	if c, ok := h.counter.Load(nodeTag); ok {
		return c.(*counter.TrafficCounter).GetCounter(user)
	}
	t := counter.NewTrafficCounter()
	if actual, loaded := h.counter.LoadOrStore(nodeTag, t); loaded {
		t = actual.(*counter.TrafficCounter)
	}
	return t.GetCounter(user)
}
