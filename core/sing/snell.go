package sing

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"sync"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type snellInboundOptions struct {
	option.SnellInboundOptions
	panelManaged bool
	detourOnly   bool
}

type snellInbound struct {
	inbound.Adapter
	router         adapter.ConnectionRouterEx
	listener       *listener.Listener
	logger         log.ContextLogger
	options        snellv6.ServerOptions
	inboundOptions option.InboundOptions

	mu          sync.Mutex
	service     *snellv6.MultiService[string]
	users       map[string]struct{}
	connections map[*snellConn]string
}

func newSnellInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options snellInboundOptions) (adapter.Inbound, error) {
	if !options.panelManaged {
		return snell.NewInbound(ctx, router, logger, tag, options.SnellInboundOptions)
	}
	if options.Version != panel.SnellVersion {
		return nil, fmt.Errorf("unsupported panel Snell version: %d", options.Version)
	}
	h := &snellInbound{
		Adapter:        inbound.NewAdapter(C.TypeSnell, tag),
		router:         uot.NewRouter(router, logger),
		logger:         logger,
		users:          make(map[string]struct{}),
		connections:    make(map[*snellConn]string),
		inboundOptions: options.ListenOptions.InboundOptions,
	}
	h.options = snellv6.ServerOptions{PSK: []byte(options.PSK), Mode: snellv6.ModeDefault, Handler: h}
	service, err := snellv6.NewMultiService[string](h.options)
	if err != nil {
		return nil, err
	}
	h.service = service
	if !options.detourOnly {
		h.listener = listener.New(listener.Options{
			Context:           ctx,
			Logger:            logger,
			Network:           []string{N.NetworkTCP},
			Listen:            options.ListenOptions,
			ConnectionHandler: h,
		})
	}
	return h, nil
}

func (h *snellInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.listener != nil {
		if err := h.listener.Start(); err != nil {
			return err
		}
	}
	scope.Add(h.close)
	return nil
}

func (h *snellInbound) close() error {
	var err error
	if h.listener != nil {
		err = h.listener.Close()
	}
	h.mu.Lock()
	connections := h.connections
	h.connections = nil
	h.mu.Unlock()
	for conn := range connections {
		_ = conn.Close()
	}
	return err
}

func (h *snellInbound) DelUsers(names []string) error {
	return h.updateUsers(nil, names)
}

func (h *snellInbound) updateUsers(added []panel.UserInfo, removed []string) error {
	h.mu.Lock()
	var revoked []*snellConn
	defer func() {
		h.mu.Unlock()
		for _, conn := range revoked {
			_ = conn.Close()
		}
	}()
	if h.connections == nil {
		return net.ErrClosed
	}
	users := maps.Clone(h.users)
	for _, user := range added {
		users[user.Uuid] = struct{}{}
	}
	for _, name := range removed {
		delete(users, name)
	}

	// Handshakes and reused sessions read the service's user map concurrently.
	// Publish a new service after validation so readers keep an immutable map.
	service, err := snellv6.NewMultiService[string](h.options)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		names := make([]string, 0, len(users))
		keys := make([][]byte, 0, len(users))
		for name := range users {
			names = append(names, name)
			keys = append(keys, []byte(name))
		}
		if err := service.UpdateUsers(names, keys); err != nil {
			return err
		}
	}
	h.service = service
	h.users = users
	if len(removed) > 0 {
		for conn, name := range h.connections {
			if _, present := users[name]; name != "" && !present {
				delete(h.connections, conn)
				revoked = append(revoked, conn)
			}
		}
	}
	return nil
}

type snellConn struct {
	net.Conn
	inbound *snellInbound
}

func (c *snellConn) Close() error {
	c.inbound.mu.Lock()
	delete(c.inbound.connections, c)
	c.inbound.mu.Unlock()
	return c.Conn.Close()
}

type snellConnKey struct{}

func (h *snellInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	tracked := &snellConn{Conn: conn, inbound: h}
	h.mu.Lock()
	if h.connections == nil {
		h.mu.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	h.connections[tracked] = ""
	service := h.service
	h.mu.Unlock()

	if onClose != nil {
		onClose = N.OnceClose(onClose)
	}
	metadata.InboundOptions = h.inboundOptions
	ctx = context.WithValue(adapter.WithContext(ctx, &metadata), snellConnKey{}, tracked)
	if err := service.NewConnection(ctx, tracked, metadata.Source, onClose); err != nil {
		N.CloseOnHandshakeFailure(tracked, onClose, err)
		if !E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, err)
		}
	}
}

func (h *snellInbound) metadata(ctx context.Context, source, destination M.Socksaddr) (adapter.InboundContext, bool) {
	_, original := adapter.ExtendContext(ctx)
	metadata := *original
	name, authenticated := auth.UserFromContext[string](ctx)
	if !authenticated {
		return metadata, false
	}
	conn, _ := ctx.Value(snellConnKey{}).(*snellConn)
	h.mu.Lock()
	_, allowed := h.users[name]
	_, active := h.connections[conn]
	if allowed && active {
		h.connections[conn] = name
	}
	h.mu.Unlock()
	if !allowed || !active {
		return metadata, false
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = source
	metadata.Destination = destination
	metadata.User = name
	return metadata, true
}

func (h *snellInbound) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata, allowed := h.metadata(ctx, source, destination)
	if !allowed {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)
		return
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *snellInbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata, allowed := h.metadata(ctx, source, destination)
	if !allowed {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)
		return
	}
	// Surge rejects Snell UDP responses with domain addresses.
	metadata.UDPDisableDomainUnmapping = true
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
