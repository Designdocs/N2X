// Package bt provides sniffers for BitTorrent traffic that the built-in
// xray-core sniffers do not recognise: DHT (BEP 5) and UDP tracker (BEP 15).
//
// Both report the protocol name "bittorrent", the same string the built-in
// handshake and uTP sniffers use, so existing routing rules and panel-side
// protocol rules match them without any configuration change.
package bt

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common"
)

const (
	// udpTrackerMagic is the fixed protocol_id of a BEP 15 connect request.
	// Only the connect request carries it; announce and scrape use a
	// server-issued connection_id. Every session starts with a connect, so
	// matching it alone is enough.
	udpTrackerMagic uint64 = 0x41727101980

	udpTrackerActionConnect uint32 = 0
	udpTrackerConnectLen           = 16

	// dhtMinLen is the shortest plausible KRPC message. Below it we may be
	// looking at a partial read rather than a non-DHT payload.
	dhtMinLen = 32
)

// KRPC messages always carry the mandatory "y" key, whose value is one of
// q (query), r (response) or e (error).
var dhtMarkers = [][]byte{
	[]byte("1:y1:q"),
	[]byte("1:y1:r"),
	[]byte("1:y1:e"),
}

var errNotBittorrent = errors.New("not bittorrent header")

// SniffHeader reports BitTorrent traffic.
type SniffHeader struct{}

func (h *SniffHeader) Protocol() string { return "bittorrent" }

func (h *SniffHeader) Domain() string { return "" }

// SniffDHT detects BitTorrent DHT (KRPC over UDP, BEP 5) messages, which are
// bencoded dictionaries carrying a "y" key.
func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}
	// Every KRPC message is a bencoded dictionary.
	if b[0] != 'd' {
		return nil, errNotBittorrent
	}
	for _, marker := range dhtMarkers {
		if bytes.Contains(b, marker) {
			return &SniffHeader{}, nil
		}
	}
	if len(b) < dhtMinLen {
		return nil, common.ErrNoClue
	}
	return nil, errNotBittorrent
}

// SniffUDPTracker detects the connect request of the UDP tracker protocol
// (BEP 15) by its fixed protocol_id.
func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) < udpTrackerConnectLen {
		return nil, common.ErrNoClue
	}
	if binary.BigEndian.Uint64(b[0:8]) != udpTrackerMagic {
		return nil, errNotBittorrent
	}
	if binary.BigEndian.Uint32(b[8:12]) != udpTrackerActionConnect {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}
