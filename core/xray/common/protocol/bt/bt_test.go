package bt

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common"
)

// Canonical KRPC messages from BEP 5.
const (
	dhtPing         = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
	dhtFindNode     = "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"
	dhtGetPeers     = "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
	dhtAnnouncePeer = "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe"
	dhtResponse     = "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"
	dhtError        = "d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"
)

func TestSniffDHTDetectsKRPCMessages(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"ping query", dhtPing},
		{"find_node query", dhtFindNode},
		{"get_peers query", dhtGetPeers},
		{"announce_peer query", dhtAnnouncePeer},
		{"response", dhtResponse},
		{"error", dhtError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := SniffDHT([]byte(tt.payload))
			if err != nil {
				t.Fatalf("expected DHT to be detected, got error: %v", err)
			}
			if h.Protocol() != "bittorrent" {
				t.Errorf("Protocol() = %q, want %q", h.Protocol(), "bittorrent")
			}
			if h.Domain() != "" {
				t.Errorf("Domain() = %q, want empty", h.Domain())
			}
		})
	}
}

func TestSniffDHTRejectsNonDHT(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"http request", []byte("GET /announce?info_hash=x HTTP/1.1\r\nHost: t.example\r\n\r\n")},
		{"tls client hello", []byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03abcdefghijklmnop")},
		{"bencode list not dict", []byte("l4:spam4:eggsel4:spam4:eggse")},
		{"bencode dict without y key", []byte("d3:bar4:spam3:fooi42e3:bazi7e3:qux4:eggse")},
		{"random bytes", []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SniffDHT(tt.payload); err == nil {
				t.Fatal("expected non-DHT payload to be rejected, got a match")
			}
		})
	}
}

func TestSniffDHTNeedsMoreDataWhenShort(t *testing.T) {
	if _, err := SniffDHT([]byte("d1:ad2:id")); err != common.ErrNoClue {
		t.Fatalf("short payload: got %v, want common.ErrNoClue", err)
	}
}

// udpTrackerConnect builds a BEP 15 connect request.
func udpTrackerConnect(protocolID uint64, action uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], protocolID)
	binary.BigEndian.PutUint32(b[8:12], action)
	binary.BigEndian.PutUint32(b[12:16], 0xdeadbeef) // transaction_id
	return b
}

func TestSniffUDPTrackerDetectsConnectRequest(t *testing.T) {
	h, err := SniffUDPTracker(udpTrackerConnect(udpTrackerMagic, 0))
	if err != nil {
		t.Fatalf("expected connect request to be detected, got error: %v", err)
	}
	if h.Protocol() != "bittorrent" {
		t.Errorf("Protocol() = %q, want %q", h.Protocol(), "bittorrent")
	}
}

func TestSniffUDPTrackerRejectsNonTracker(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"wrong magic", udpTrackerConnect(0x0123456789abcdef, 0)},
		{"magic but non-connect action", udpTrackerConnect(udpTrackerMagic, 1)},
		{"dns query", []byte("\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")},
		{"all zeroes", make([]byte, 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SniffUDPTracker(tt.payload); err == nil {
				t.Fatal("expected non-tracker payload to be rejected, got a match")
			}
		})
	}
}

func TestSniffUDPTrackerNeedsMoreDataWhenShort(t *testing.T) {
	if _, err := SniffUDPTracker([]byte("\x00\x00\x04\x17")); err != common.ErrNoClue {
		t.Fatalf("short payload: got %v, want common.ErrNoClue", err)
	}
}

// The two new sniffers must not claim traffic the existing BT sniffers handle,
// and must not claim each other's traffic.
func TestSniffersDoNotOverlap(t *testing.T) {
	if _, err := SniffDHT(udpTrackerConnect(udpTrackerMagic, 0)); err == nil {
		t.Error("DHT sniffer claimed a UDP tracker connect request")
	}
	if _, err := SniffUDPTracker([]byte(dhtPing)); err == nil {
		t.Error("UDP tracker sniffer claimed a DHT ping")
	}
}
