package sing

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

const snellWebsiteTimeout = 3 * time.Second

type snellPrefetchedConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (c *snellPrefetchedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	n := copy(p, c.prefix)
	if n == len(c.prefix) {
		c.prefix = nil
	} else {
		c.prefix = c.prefix[n:]
	}
	c.mu.Unlock()
	if n > 0 {
		return n, nil
	}
	return c.Conn.Read(p)
}

func sniffSnellWebsite(ctx context.Context, conn net.Conn) (net.Conn, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(snellWebsiteTimeout)); err != nil {
		return nil, false, err
	}

	// A TLS handshake record starts with 0x16, the legacy version, the
	// record length and the first handshake byte (0x01 for ClientHello).
	var prefix [6]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, false, err
	}
	data := prefix[:]
	var metadata adapter.InboundContext
	recordLength := binary.BigEndian.Uint16(prefix[3:5])
	if prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] >= 1 && prefix[2] <= 3 &&
		recordLength > 0 && recordLength <= 16*1024 && prefix[5] == 0x01 {
		// A random Snell prefix can match the record header. Use the full
		// ClientHello parser and replay all bytes to the selected handler.
		var buffered bytes.Buffer
		reader := io.MultiReader(bytes.NewReader(data), conn)
		_ = sniff.TLSClientHello(ctx, &metadata, io.TeeReader(io.LimitReader(reader, 64*1024), &buffered))
		data = buffered.Bytes()
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	return &snellPrefetchedConn{Conn: conn, prefix: data}, metadata.Protocol == C.ProtocolTLS, nil
}

func (h *snellInbound) relaySnellWebsite(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) {
	dialer := net.Dialer{Timeout: snellWebsiteTimeout}
	website, err := dialer.DialContext(ctx, N.NetworkTCP, h.websiteAddress)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
	} else {
		err = bufio.CopyConn(ctx, conn, website)
		if onClose != nil {
			onClose(err)
		}
	}
	if err != nil && !E.IsClosedOrCanceled(err) {
		h.logger.DebugContext(ctx, "Snell website fallback: ", err)
	}
}
