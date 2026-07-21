package dispatcher

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

const dhtPingQuery = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"

func udpTrackerConnectRequest() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(b[8:12], 0)
	binary.BigEndian.PutUint32(b[12:16], 0xdeadbeef)
	return b
}

// withBTExtraSniffing sets the flag for one test and restores it afterwards.
func withBTExtraSniffing(t *testing.T, enabled bool) {
	t.Helper()
	previous := BTExtraSniffingEnabled()
	SetBTExtraSniffing(enabled)
	t.Cleanup(func() { SetBTExtraSniffing(previous) })
}

func sniffedOn(t *testing.T, payload []byte, network net.Network) string {
	t.Helper()
	ctx := context.Background()
	s := &Sniffer{sniffer: newProtocolSniffers(ctx)}
	result, err := s.Sniff(ctx, payload, network)
	if err != nil || result == nil {
		return ""
	}
	return result.Protocol()
}

func sniffedProtocol(t *testing.T, payload []byte) string {
	t.Helper()
	return sniffedOn(t, payload, net.Network_UDP)
}

// liveUTPPacket builds a uTP header whose timestamp is current.
func liveUTPPacket() []byte {
	b := make([]byte, 20)
	b[0] = 0x01 // ST_DATA, version 1
	b[1] = 0x00 // no extension
	binary.BigEndian.PutUint16(b[2:4], 0x1234)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().UnixMicro()))
	return b
}

func TestSnifferDetectsExtraBTTrafficWhenEnabled(t *testing.T) {
	withBTExtraSniffing(t, true)

	tests := []struct {
		name    string
		payload []byte
	}{
		{"dht ping query", []byte(dhtPingQuery)},
		{"udp tracker connect", udpTrackerConnectRequest()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sniffedProtocol(t, tt.payload); got != "bittorrent" {
				t.Errorf("sniffed protocol = %q, want %q", got, "bittorrent")
			}
		})
	}
}

func TestSnifferIgnoresExtraBTTrafficWhenDisabled(t *testing.T) {
	withBTExtraSniffing(t, false)

	tests := []struct {
		name    string
		payload []byte
	}{
		{"dht ping query", []byte(dhtPingQuery)},
		{"udp tracker connect", udpTrackerConnectRequest()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sniffedProtocol(t, tt.payload); got == "bittorrent" {
				t.Error("extra BT sniffers still ran while disabled")
			}
		})
	}
}

// The corrected uTP sniffer replaces the upstream one, whose timestamp check
// can never pass. Turning the switch off restores the original behaviour, so
// the switch doubles as a rollback to exactly the pre-change state.
func TestUTPDetectionFollowsSwitch(t *testing.T) {
	utp := liveUTPPacket()

	withBTExtraSniffing(t, true)
	if got := sniffedProtocol(t, utp); got != "bittorrent" {
		t.Errorf("switch on: uTP should be detected, got %q", got)
	}

	withBTExtraSniffing(t, false)
	if got := sniffedProtocol(t, utp); got == "bittorrent" {
		t.Error("switch off: expected the original upstream sniffer, which never matches")
	}
}

// The TCP handshake sniffer is a built-in and must be unaffected by the switch.
func TestTCPHandshakeDetectedRegardlessOfSwitch(t *testing.T) {
	handshake := append([]byte{19}, []byte("BitTorrent protocol")...)

	for _, enabled := range []bool{true, false} {
		withBTExtraSniffing(t, enabled)
		if got := sniffedOn(t, handshake, net.Network_TCP); got != "bittorrent" {
			t.Errorf("enabled=%v: TCP handshake should still be detected, got %q", enabled, got)
		}
	}
}

func TestBTExtraSniffingIsEnabledByDefault(t *testing.T) {
	if !BTExtraSniffingEnabled() {
		t.Error("extra BT sniffing should default to enabled")
	}
}
