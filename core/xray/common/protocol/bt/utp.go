package bt

import (
	"encoding/binary"
	"time"

	"github.com/xtls/xray-core/common"
)

const (
	utpMinLen     = 20
	utpVersion    = 1
	utpMaxType    = 4
	utpExtNone    = 0
	utpExtSelAck  = 1
	utpConnIDLen  = 2
	utpTimeLen    = 4
	utpTimeWindow = uint32(5 * 60 * 1e6) // 5 minutes, in microseconds
)

// utpTimestampPlausible reports whether a uTP timestamp is close to now.
//
// timestamp_microseconds carries only the low 32 bits of the sender's
// microsecond clock, so the value wraps about every 71.6 minutes. The
// comparison therefore has to be circular: uint32 subtraction wraps with it,
// giving the distance in each direction directly.
//
// The upstream sniffer compared this truncated value against the full
// time.Now().UnixMicro() (a ~51-bit number) using a threshold expressed in
// nanoseconds, so the difference always exceeded it and no packet ever matched.
func utpTimestampPlausible(timestamp uint32, now time.Time) bool {
	n := uint32(now.UnixMicro())
	return n-timestamp <= utpTimeWindow || timestamp-n <= utpTimeWindow
}

// SniffUTP detects uTP (BEP 29), the UDP transport BitTorrent uses for data.
//
// It replaces xray-core's SniffUTP, whose timestamp check could never pass.
// The header walk mirrors the upstream one so that behaviour stays identical
// apart from the timestamp comparison.
func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < utpMinLen {
		return nil, common.ErrNoClue
	}
	if b[0]>>4 > utpMaxType || b[0]&0x0F != utpVersion {
		return nil, errNotBittorrent
	}

	extension := b[1]
	offset := 2
	for extension != utpExtNone {
		if extension != utpExtSelAck {
			return nil, errNotBittorrent
		}
		if offset+2 > len(b) {
			return nil, common.ErrNoClue
		}
		extension = b[offset]
		offset += 2 + int(b[offset+1])
		if offset > len(b) {
			return nil, common.ErrNoClue
		}
	}

	if offset+utpConnIDLen+utpTimeLen > len(b) {
		return nil, common.ErrNoClue
	}
	timestamp := binary.BigEndian.Uint32(b[offset+utpConnIDLen : offset+utpConnIDLen+utpTimeLen])
	if !utpTimestampPlausible(timestamp, time.Now()) {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}
