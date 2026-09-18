package dispatcher

import (
	"context"
	stdnet "net"
	"net/netip"

	mux "github.com/sagernet/sing-mux"
	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

// SingMuxOptions enables the sing-mux server for one inbound.
//
// Clients built on sing-box or mihomo multiplex by opening a single proxied
// connection to sing-mux's magic destination and running yamux/h2mux/smux
// inside it. Xray only understands its own Mux.Cool, so without this the
// magic destination is routed like a real host and every multiplexed client
// silently fails to connect.
type SingMuxOptions struct {
	Padding bool
}

// SetSingMux turns the sing-mux server on for an inbound tag, or off when
// opts is nil.
func (d *DefaultDispatcher) SetSingMux(tag string, opts *SingMuxOptions) {
	if opts == nil {
		d.singMux.Delete(tag)
		return
	}
	d.singMux.Store(tag, *opts)
}

func isSingMuxDestination(dest net.Destination) bool {
	return dest.Network == net.Network_TCP &&
		dest.Address != nil &&
		dest.Address.Family().IsDomain() &&
		dest.Address.Domain() == mux.Destination.Fqdn
}

func (d *DefaultDispatcher) singMuxOptions(ctx context.Context) (SingMuxOptions, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil {
		return SingMuxOptions{}, errors.New("sing-mux needs an authenticated inbound")
	}
	if _, nested := ctx.Value(singMuxStreamKey{}).(bool); nested {
		return SingMuxOptions{}, errors.New("nested sing-mux session rejected")
	}
	opts, ok := d.singMux.Load(inbound.Tag)
	if !ok {
		return SingMuxOptions{}, errors.New("multiplex is not enabled for node ", inbound.Tag)
	}
	return opts.(SingMuxOptions), nil
}

// dispatchSingMux answers Dispatch for the magic destination: the inbound
// gets one end of a pipe pair and the mux session runs on the other.
func (d *DefaultDispatcher) dispatchSingMux(ctx context.Context) (*transport.Link, error) {
	opts, err := d.singMuxOptions(ctx)
	if err != nil {
		errors.LogWarningInner(ctx, err, "refused sing-mux session")
		return nil, err
	}
	pipeOpts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(pipeOpts...)
	downlinkReader, downlinkWriter := pipe.New(pipeOpts...)
	go d.serveSingMux(ctx, opts, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter})
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// dispatchSingMuxLink answers DispatchLink for the magic destination and
// blocks until the mux session ends, as DispatchLink callers expect.
func (d *DefaultDispatcher) dispatchSingMuxLink(ctx context.Context, link *transport.Link) error {
	opts, err := d.singMuxOptions(ctx)
	if err != nil {
		errors.LogWarningInner(ctx, err, "refused sing-mux session")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return err
	}
	d.serveSingMux(ctx, opts, link)
	return nil
}

// serveSingMux runs one sing-mux session. The outer connection is neither
// counted nor limited here: every stream inside it is dispatched on its own
// and goes through getLink like a direct connection would.
func (d *DefaultDispatcher) serveSingMux(ctx context.Context, opts SingMuxOptions, link *transport.Link) {
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(link.Writer), cnc.ConnectionOutputMulti(link.Reader))
	defer conn.Close()
	service, err := mux.NewService(mux.ServiceOptions{
		NewStreamContext: newSingMuxStreamContext,
		Logger:           singMuxLogger{},
		HandlerEx:        &singMuxHandler{d: d},
		Padding:          opts.Padding,
	})
	if err != nil {
		errors.LogWarningInner(ctx, err, "failed to start sing-mux service")
		return
	}
	var source M.Socksaddr
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
		source = toSocksaddr(inbound.Source)
	}
	service.NewConnectionEx(ctx, conn, source, mux.Destination, nil)
}

type singMuxStreamKey struct{}

// newSingMuxStreamContext gives each stream its own session: Dispatch writes
// the routing target into the last outbound, sniffing results into the
// content and splice eligibility into the inbound, so streams sharing the
// tunnel's would overwrite each other from their own goroutines.
func newSingMuxStreamContext(ctx context.Context, _ stdnet.Conn) context.Context {
	if parent := session.InboundFromContext(ctx); parent != nil {
		inbound := *parent
		// The carrier connection holds every stream of the session, so no
		// stream may splice it.
		inbound.Conn = nil
		inbound.Timer = nil
		inbound.CanSpliceCopy = 3
		ctx = session.ContextWithInbound(ctx, &inbound)
	}
	content := &session.Content{}
	if parent := session.ContentFromContext(ctx); parent != nil {
		content.SniffingRequest = parent.SniffingRequest
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, content)
	ctx = context.WithValue(ctx, singMuxStreamKey{}, true)
	return xctx.ContextWithID(ctx, session.NewID())
}

func withStreamAccessMessage(ctx context.Context, dest net.Destination) context.Context {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() {
		return ctx
	}
	msg := &log.AccessMessage{From: inbound.Source, To: dest, Status: log.AccessAccepted}
	if inbound.User != nil {
		msg.Email = inbound.User.Email
	}
	return log.ContextWithAccessMessage(ctx, msg)
}

func (d *DefaultDispatcher) streamPolicy(ctx context.Context) policy.Session {
	var level uint32
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		level = inbound.User.Level
	}
	return d.policy.ForLevel(level)
}

type singMuxHandler struct {
	d *DefaultDispatcher
}

func (h *singMuxHandler) NewConnectionEx(ctx context.Context, conn stdnet.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	dest, ok := singMuxDestination(net.Network_TCP, destination)
	if !ok {
		errors.LogInfo(ctx, "sing-mux stream without a usable destination rejected")
		return
	}
	if err := h.d.relaySingMuxStream(ctx, dest, conn); err != nil {
		errors.LogInfoInner(ctx, err, "sing-mux stream to ", dest, " ended")
	}
}

func (h *singMuxHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	if err := h.d.relaySingMuxPackets(ctx, conn); err != nil {
		errors.LogInfoInner(ctx, err, "sing-mux packet stream ended")
	}
}

func (d *DefaultDispatcher) relaySingMuxStream(ctx context.Context, dest net.Destination, conn stdnet.Conn) error {
	if isSingMuxDestination(dest) {
		return errors.New("nested sing-mux session rejected")
	}
	sessionPolicy := d.streamPolicy(ctx)
	ctx, cancel := context.WithCancel(withStreamAccessMessage(ctx, dest))
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	link, err := d.Dispatch(ctx, dest)
	if err != nil {
		return errors.New("failed to dispatch sing-mux stream to ", dest).Base(err)
	}
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return err
	}
	return nil
}

func (d *DefaultDispatcher) relaySingMuxPackets(ctx context.Context, conn N.PacketConn) error {
	sessionPolicy := d.streamPolicy(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	udpServer := udp.NewDispatcher(d, func(ctx context.Context, packet *udp_proto.Packet) {
		if err := writeSingMuxPacket(conn, packet); err != nil {
			errors.LogInfoInner(ctx, err, "failed to write sing-mux packet")
			cancel()
			return
		}
		timer.Update()
	})
	defer udpServer.RemoveRay()
	// ReadPacket does not watch ctx; closing the stream is what unblocks it
	// once the inactivity timer fires or a write fails.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		packet := sbuf.NewPacket()
		from, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		timer.Update()
		dest, ok := singMuxDestination(net.Network_UDP, from)
		if !ok {
			packet.Release()
			continue
		}
		payload := buf.NewWithSize(max(int32(packet.Len()), buf.Size))
		payload.Write(packet.Bytes())
		packet.Release()
		payload.UDP = &dest
		udpServer.Dispatch(withStreamAccessMessage(ctx, dest), dest, payload)
	}
}

// singMuxPacketHeadroom fits every header sing-mux prepends to a reply: the
// one-time status byte, the address of an address-carrying stream and the
// length prefix.
const singMuxPacketHeadroom = 1 + M.MaxSocksaddrLength + 2

func writeSingMuxPacket(conn N.PacketConn, packet *udp_proto.Packet) error {
	defer packet.Payload.Release()
	from := packet.Source
	if packet.Payload.UDP != nil {
		from = *packet.Payload.UDP
	}
	reply := sbuf.NewSize(singMuxPacketHeadroom + int(packet.Payload.Len()))
	reply.Resize(singMuxPacketHeadroom, 0)
	common.Must2(reply.Write(packet.Payload.Bytes()))
	// WritePacket owns reply from here on, as sing's writers release it.
	return conn.WritePacket(reply, toSocksaddr(from))
}

// singMuxDestination converts a stream or packet target. A wire address can
// be well formed yet empty (a zero-length name), and Destination.IsValid does
// not look at the address, so a nil one would reach Dispatch and panic the
// first time the destination is logged.
func singMuxDestination(network net.Network, addr M.Socksaddr) (net.Destination, bool) {
	address := toXrayAddress(addr)
	if address == nil || addr.Port == 0 {
		return net.Destination{}, false
	}
	return net.Destination{Network: network, Address: address, Port: net.Port(addr.Port)}, true
}

func toXrayAddress(addr M.Socksaddr) net.Address {
	if addr.IsFqdn() {
		return net.ParseAddress(addr.Fqdn)
	}
	if addr.Addr.IsValid() {
		return net.IPAddress(addr.Addr.Unmap().AsSlice())
	}
	return nil
}

func toSocksaddr(dest net.Destination) M.Socksaddr {
	port := uint16(dest.Port)
	if dest.Address == nil {
		return M.Socksaddr{Port: port}
	}
	if dest.Address.Family().IsDomain() {
		return M.Socksaddr{Fqdn: dest.Address.Domain(), Port: port}
	}
	ip, _ := netip.AddrFromSlice(dest.Address.IP())
	return M.Socksaddr{Addr: ip.Unmap(), Port: port}
}

// singMuxLogger routes sing-mux's own logging into Xray's log.
type singMuxLogger struct{}

func (singMuxLogger) Trace(args ...any) {}
func (singMuxLogger) Debug(args ...any) { errors.LogDebug(context.Background(), args...) }
func (singMuxLogger) Info(args ...any)  { errors.LogInfo(context.Background(), args...) }
func (singMuxLogger) Warn(args ...any)  { errors.LogWarning(context.Background(), args...) }
func (singMuxLogger) Error(args ...any) { errors.LogWarning(context.Background(), args...) }
func (singMuxLogger) Fatal(args ...any) { errors.LogError(context.Background(), args...) }
func (singMuxLogger) Panic(args ...any) { errors.LogError(context.Background(), args...) }

func (singMuxLogger) TraceContext(ctx context.Context, args ...any) {}
func (singMuxLogger) DebugContext(ctx context.Context, args ...any) { errors.LogDebug(ctx, args...) }
func (singMuxLogger) InfoContext(ctx context.Context, args ...any)  { errors.LogInfo(ctx, args...) }
func (singMuxLogger) WarnContext(ctx context.Context, args ...any)  { errors.LogWarning(ctx, args...) }

// Stream errors are mostly clients hanging up, so they log as warnings.
func (singMuxLogger) ErrorContext(ctx context.Context, args ...any) {
	errors.LogWarning(ctx, args...)
}
func (singMuxLogger) FatalContext(ctx context.Context, args ...any) { errors.LogError(ctx, args...) }
func (singMuxLogger) PanicContext(ctx context.Context, args ...any) { errors.LogError(ctx, args...) }
