package xray

import (
	"net"
	"testing"

	"github.com/apernet/quic-go/http3"
)

func TestStopNativeUDPReleasesPacketSocket(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := packetConn.LocalAddr().String()
	core := &Xray{nativeUDP: map[string]*nativeUDPService{
		"test": {server: &http3.Server{}, packetConn: packetConn},
	}, nativeUDPState: map[string]*nativeUDPState{
		"test": {RequestedMode: "native", ActiveMode: "native", ListenerReady: true},
	}}
	if err := core.stopNativeUDP("test"); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("native UDP socket was not released: %v", err)
	}
	_ = rebound.Close()
	state := core.nativeUDPStatus("test")
	if state.RequestedMode != "native" || state.ActiveMode != "disabled" || state.ListenerReady || state.CleanupFailure != 0 || state.CleanupMillis > 5_000 {
		t.Fatalf("native UDP cleanup state = %#v", state)
	}
}
