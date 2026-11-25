// Package realitywebsite selects a local HTTPS origin before Xray's TCP
// listener runs the REALITY handshake.
package realitywebsite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	sbufio "github.com/sagernet/sing/common/bufio"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const handshakeTimeout = 5 * time.Second

// Xray calls Listen for listener-level masks. Classification must happen
// concurrently so an incomplete ClientHello cannot block other accepts.
func (c *Config) Listen(inner net.Listener) (net.Listener, error) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{Listener: inner, ctx: ctx, cancel: cancel, ready: make(chan acceptResult)}
	go l.monitor(c)
	go l.serve(c)
	return l, nil
}

func (*Config) WrapConnServer(net.Conn) (net.Conn, error) {
	return nil, errors.New("RealityWebsite requires a TCP listener")
}

func (*Config) WrapConnClient(net.Conn, *xnet.Destination, *finalmask.Dialer) (net.Conn, error) {
	return nil, errors.New("RealityWebsite is inbound only")
}

type acceptResult struct {
	conn net.Conn
	err  error
}

type listener struct {
	net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan acceptResult
	site   atomic.Pointer[origin]
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case result := <-l.ready:
		return result.conn, result.err
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

func (l *listener) serve(c *Config) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.ready <- acceptResult{err: err}:
			case <-l.ctx.Done():
				return
			}
			if errors.Is(err, net.ErrClosed) {
				l.cancel()
				return
			}
			continue
		}
		if site := l.site.Load(); site != nil {
			go l.classify(conn, c, site)
		} else {
			l.pass(conn)
		}
	}
}

func (l *listener) pass(conn net.Conn) {
	select {
	case l.ready <- acceptResult{conn: conn}:
	case <-l.ctx.Done():
		conn.Close()
	}
}

func (l *listener) classify(conn net.Conn, c *Config, target *origin) {
	stop := context.AfterFunc(l.ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		conn.Close()
		return
	}
	var prefix bytes.Buffer
	var hello adapter.InboundContext
	err := sniff.TLSClientHello(l.ctx, &hello, io.TeeReader(io.LimitReader(conn, 64<<10), &prefix))
	if prefix.Len() == 0 && !errors.Is(err, os.ErrDeadlineExceeded) {
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return
	}
	if err == nil && strings.EqualFold(hello.Domain, c.ServerName) {
		if l.forward(conn, target, &prefix) {
			return
		}
		l.site.CompareAndSwap(target, nil)
	}

	// Retain the actual socket and its remote address for Vision, online IP
	// accounting and device limits. Only the consumed handshake bytes replay.
	if prefix.Len() == 0 {
		l.pass(conn)
		return
	}
	l.pass(&replayConn{Conn: conn, prefix: prefix.Bytes()})
}

// Only retry the original REALITY path while the client handshake is intact.
func (l *listener) forward(conn net.Conn, target *origin, prefix *bytes.Buffer) bool {
	dialer := net.Dialer{Timeout: time.Second}
	site, err := dialer.DialContext(l.ctx, "tcp", target.address)
	if err != nil {
		return false
	}
	defer site.Close()
	site.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if target.proxy {
		if _, err := proxyproto.HeaderProxyFromAddrs(2, conn.RemoteAddr(), conn.LocalAddr()).WriteTo(site); err != nil {
			return false
		}
	}
	n, err := prefix.WriteTo(site)
	if err != nil && n == 0 {
		return false
	}
	defer conn.Close()
	if err == nil {
		site.SetWriteDeadline(time.Time{})
		_ = sbufio.CopyConn(l.ctx, conn, site)
	}
	return true
}

type replayConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *replayConn) CloseWrite() error {
	conn := c.Conn
	if p, ok := conn.(*proxyproto.Conn); ok {
		conn = p.Raw()
	}
	if w, ok := conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return conn.Close()
}

func (*replayConn) TcpMaskConn()        {}
func (c *replayConn) RawConn() net.Conn { return c.Conn }
func (c *replayConn) Splice() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.prefix) == 0
}
