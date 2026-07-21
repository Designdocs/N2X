package bt

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
)

// utpPacket builds a minimal uTP header: type/version, no extension,
// connection_id, then timestamp_microseconds.
func utpPacket(typeAndVersion, extension byte, timestamp uint32) []byte {
	b := make([]byte, 20)
	b[0] = typeAndVersion
	b[1] = extension
	binary.BigEndian.PutUint16(b[2:4], 0x1234) // connection_id
	binary.BigEndian.PutUint32(b[4:8], timestamp)
	return b
}

func nowMicro32() uint32 { return uint32(time.Now().UnixMicro()) }

func TestSniffUTPDetectsLivePackets(t *testing.T) {
	tests := []struct {
		name           string
		typeAndVersion byte
	}{
		{"ST_DATA", 0x01},
		{"ST_FIN", 0x11},
		{"ST_STATE", 0x21},
		{"ST_RESET", 0x31},
		{"ST_SYN", 0x41},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := SniffUTP(utpPacket(tt.typeAndVersion, 0, nowMicro32()))
			if err != nil {
				t.Fatalf("expected uTP to be detected, got error: %v", err)
			}
			if h.Protocol() != "bittorrent" {
				t.Errorf("Protocol() = %q, want %q", h.Protocol(), "bittorrent")
			}
		})
	}
}

func TestSniffUTPRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"wrong version", utpPacket(0x02, 0, nowMicro32())},
		{"type out of range", utpPacket(0x51, 0, nowMicro32())},
		{"invalid extension", utpPacket(0x01, 0x07, nowMicro32())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SniffUTP(tt.payload); err == nil {
				t.Fatal("expected malformed uTP header to be rejected")
			}
		})
	}
}

func TestSniffUTPNeedsMoreDataWhenShort(t *testing.T) {
	if _, err := SniffUTP([]byte{0x01, 0x00, 0x12}); err != common.ErrNoClue {
		t.Fatalf("short payload: got %v, want common.ErrNoClue", err)
	}
}

// utpPacketWithExtension builds a packet carrying one selective-ack extension,
// which pushes connection_id and the timestamp further into the buffer.
func utpPacketWithExtension(nextExt, extLen byte, timestamp uint32) []byte {
	b := make([]byte, 24)
	b[0] = 0x01    // ST_DATA, version 1
	b[1] = 0x01    // first extension: selective ack
	b[2] = nextExt // no further extension
	b[3] = extLen
	offset := 2 + 2 + int(extLen)
	if offset+6 <= len(b) {
		binary.BigEndian.PutUint16(b[offset:offset+2], 0x1234)
		binary.BigEndian.PutUint32(b[offset+2:offset+6], timestamp)
	}
	return b
}

func TestSniffUTPWalksExtensionChain(t *testing.T) {
	h, err := SniffUTP(utpPacketWithExtension(0x00, 4, nowMicro32()))
	if err != nil {
		t.Fatalf("expected uTP with an extension to be detected, got: %v", err)
	}
	if h.Protocol() != "bittorrent" {
		t.Errorf("Protocol() = %q, want %q", h.Protocol(), "bittorrent")
	}
}

func TestSniffUTPRejectsUnknownExtensionInChain(t *testing.T) {
	if _, err := SniffUTP(utpPacketWithExtension(0x07, 4, nowMicro32())); err == nil {
		t.Fatal("expected an unknown extension in the chain to be rejected")
	}
}

func TestSniffUTPNeedsMoreDataWhenExtensionOverrunsBuffer(t *testing.T) {
	// An extension length that runs past the end of the payload.
	if _, err := SniffUTP(utpPacketWithExtension(0x00, 200, nowMicro32())); err != common.ErrNoClue {
		t.Fatalf("overrunning extension: got %v, want common.ErrNoClue", err)
	}
}

func TestSniffUTPRejectsStaleTimestamp(t *testing.T) {
	stale := nowMicro32() - 1_800_000_000 // half an hour off
	if _, err := SniffUTP(utpPacket(0x01, 0, stale)); err == nil {
		t.Fatal("expected a stale timestamp to be rejected")
	}
}

// The timestamp is the low 32 bits of a microsecond clock, so it wraps roughly
// every 71.6 minutes. Comparison must be circular, not a plain subtraction.
func TestUTPTimestampPlausibility(t *testing.T) {
	now := time.UnixMicro(1_784_606_580_153_211)
	nowTrunc := uint32(now.UnixMicro())

	tests := []struct {
		name      string
		timestamp uint32
		want      bool
	}{
		{"exactly now", nowTrunc, true},
		{"one second ago", nowTrunc - 1_000_000, true},
		{"one second ahead (clock skew)", nowTrunc + 1_000_000, true},
		{"half an hour ago", nowTrunc - 1_800_000_000, false},
		{"opposite side of the wrap space", nowTrunc + math.MaxUint32/2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utpTimestampPlausible(tt.timestamp, now); got != tt.want {
				t.Errorf("utpTimestampPlausible(%d) = %v, want %v", tt.timestamp, got, tt.want)
			}
		})
	}
}

// A timestamp taken just before the counter wraps must still be accepted a
// moment later, once the counter has rolled over to a small value.
func TestUTPTimestampSurvivesWraparound(t *testing.T) {
	justBeforeWrap := uint32(math.MaxUint32 - 1_000_000) // 1s before rollover
	// A clock 2s later has wrapped to a small value.
	afterWrap := time.UnixMicro(int64(math.MaxUint32) + 1_000_000)

	if !utpTimestampPlausible(justBeforeWrap, afterWrap) {
		t.Error("timestamp from just before the wrap was rejected after rollover")
	}
}

// Regression guard: the upstream sniffer compared a uint32 against the full
// UnixMicro value, so no timestamp could ever pass.
func TestSniffUTPAcceptsSomeTimestamp(t *testing.T) {
	if _, err := SniffUTP(utpPacket(0x01, 0, nowMicro32())); err != nil {
		t.Fatalf("no timestamp can pass the plausibility check: %v", err)
	}
}
