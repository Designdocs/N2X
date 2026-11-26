package scanguard

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Designdocs/N2X/conf"
)

const visitorMagic = "\xfdN2Xrelay\x01"

type visitorListener struct {
	net.Listener
	enforce      bool
	directOnly   bool
	feedbackCert *tls.Certificate
	tag          string
	roots        *x509.CertPool
	done         chan struct{}
	ready        chan net.Conn
	once         sync.Once
}

func WrapVisitorListener(tag string, cfg conf.WSScanGuardConfig, raw net.Listener) (net.Listener, error) {
	directOnly := cfg.Enabled && slices.Contains(cfg.DirectOnlyNodes, tag)
	if (!HasRelayCA(cfg) && !directOnly) || tag == "" {
		return raw, nil
	}
	l := &visitorListener{Listener: raw, tag: tag, enforce: cfg.Enabled, directOnly: directOnly, done: make(chan struct{}), ready: make(chan net.Conn)}
	if HasRelayCA(cfg) {
		roots, err := relayRoots(cfg.RelayCAFile)
		if err != nil {
			return nil, err
		}
		l.roots = roots
		if cfg.Enabled && cfg.FeedbackCertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.FeedbackCertFile, cfg.FeedbackKeyFile)
			if err != nil {
				log.Printf("node %s: relay ban feedback unavailable: %v", tag, err)
			} else {
				l.feedbackCert = &cert
			}
		}
	}
	go l.run()
	return l, nil
}
func (l *visitorListener) Close() error {
	var err error
	l.once.Do(func() { close(l.done); err = l.Listener.Close() })
	return err
}
func (l *visitorListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *visitorListener) run() {
	defer l.Close()
	slots := make(chan struct{}, 256)
	for {
		select {
		case slots <- struct{}{}:
		case <-l.done:
			return
		}
		raw, err := l.Listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { <-slots }()
			conn, err := l.identify(raw)
			if err != nil {
				raw.Close()
				if !errors.Is(err, io.EOF) {
					log.Printf("node %s: relay admission: %v", l.tag, err)
				}
				return
			}
			select {
			case l.ready <- conn:
			case <-l.done:
				conn.Close()
			}
		}()
	}
}

type replayConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(b)
	}
	return c.Conn.Read(b)
}

type visitorConn struct {
	net.Conn
	local *net.TCPAddr
}

func (c *visitorConn) LocalAddr() net.Addr { return c.local }
func (c *visitorConn) Close() error        { verifiedVisitors.Delete(c.local); return c.Conn.Close() }

// Use the unique address object carried by this connection, never the text of a socket address.
var verifiedVisitors sync.Map

type verifiedVisitor struct {
	tag string
	ip  netip.Addr
}

func (l *visitorListener) identify(raw net.Conn) (net.Conn, error) {
	if err := raw.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return nil, err
	}
	direct, err := directSocket(raw)
	if err != nil {
		return nil, err
	}
	if direct {
		return l.ordinary(raw, raw)
	}
	var prefix [len(visitorMagic)]byte
	for i := range prefix {
		if _, err := io.ReadFull(raw, prefix[i:i+1]); err != nil {
			return nil, err
		}
		if prefix[i] != visitorMagic[i] {
			if err := raw.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			return l.ordinary(raw, &replayConn{raw, bytes.NewReader(prefix[:i+1])})
		}
	}
	// The dialing Agent presents its Master-issued certificate as the TLS server.
	if l.roots == nil {
		return nil, errors.New("no trusted relay CA configured")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "n2x-relay.invalid", RootCAs: l.roots}
	if l.feedbackCert != nil {
		cfg.NextProtos = []string{feedbackProtocol}
		cfg.Certificates = []tls.Certificate{*l.feedbackCert}
	}
	channel := tls.Client(raw, cfg)
	if err := channel.Handshake(); err != nil {
		return nil, err
	}
	var address [16]byte
	if _, err := io.ReadFull(channel, address[:]); err != nil {
		return nil, err
	}
	var size uint8
	if err := binary.Read(channel, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	dest := make([]byte, size)
	if _, err := io.ReadFull(channel, dest); err != nil {
		return nil, err
	}
	if err := channel.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	target, err := netip.ParseAddrPort(string(dest))
	local, lok := raw.LocalAddr().(*net.TCPAddr)
	peer, pok := raw.RemoteAddr().(*net.TCPAddr)
	ip := netip.AddrFrom16(address).Unmap()
	var stream net.Conn = channel
	var feedback *feedbackWriter
	if channel.ConnectionState().NegotiatedProtocol == feedbackProtocol {
		feedback = &feedbackWriter{Conn: channel}
		stream = feedback
	}
	if !l.enforce || err != nil || !lok || !pok || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip == peer.AddrPort().Addr().Unmap() || target != netip.AddrPortFrom(local.AddrPort().Addr().Unmap(), local.AddrPort().Port()) {
		return stream, nil
	}
	v := verifiedVisitor{l.tag, ip}
	return l.admit(stream, local, v, feedback)
}

func (l *visitorListener) admit(stream net.Conn, local *net.TCPAddr, v verifiedVisitor, feedback *feedbackWriter) (net.Conn, error) {
	if v.blocked() {
		if feedback != nil {
			_ = feedback.ban(v.ip)
		}
		return nil, fmt.Errorf("blocked verified visitor %s", v.ip)
	}
	addr := *local
	c := &visitorConn{stream, &addr}
	verifiedVisitors.Store(c.local, attributedConnection{v, feedback})
	return c, nil
}

func (l *visitorListener) ordinary(raw, stream net.Conn) (net.Conn, error) {
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// A transport wrapper (including PROXY protocol) can override RemoteAddr.
	tcp, ok := raw.(*net.TCPConn)
	if !l.directOnly || !ok {
		return stream, nil
	}
	peer := tcp.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	return l.admit(stream, tcp.LocalAddr().(*net.TCPAddr), verifiedVisitor{l.tag, peer}, nil)
}

type attributedConnection struct {
	verifiedVisitor
	feedback *feedbackWriter
}
