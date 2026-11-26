package scanguard

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Only the landing-to-relay direction is framed. Frames are carried inside
// the negotiated TLS session, outside the visitor-controlled byte stream.
const feedbackProtocol = "n2x-ban/1"

type feedbackWriter struct {
	net.Conn
	mu sync.Mutex
}

func (w *feedbackWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := 0
	for len(data) > 0 {
		size := min(len(data), 16384)
		if err := w.frame(0, data[:size]); err != nil {
			return total, err
		}
		total += size
		data = data[size:]
	}
	return total, nil
}

func (w *feedbackWriter) ban(ip netip.Addr) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	defer w.Conn.SetWriteDeadline(time.Time{})
	addr := ip.As16()
	return w.frame(1, addr[:])
}

func (w *feedbackWriter) frame(kind byte, data []byte) error {
	// Emit one TLS write so a short control frame cannot interleave with data.
	packet := make([]byte, 3+len(data))
	packet[0] = kind
	binary.BigEndian.PutUint16(packet[1:3], uint16(len(data)))
	copy(packet[3:], data)
	_, err := w.Conn.Write(packet)
	return err
}
