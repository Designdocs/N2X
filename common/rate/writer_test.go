package rate

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type testBufferWriter func(buf.MultiBuffer) error

func (f testBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { return f(mb) }

func TestControllerWriterPreservesLargeDatagram(t *testing.T) {
	payload := bytes.Repeat([]byte("udp"), 10000)
	destination := net.UDPDestination(net.ParseAddress("192.0.2.1"), 1234)
	packet := buf.NewWithSize(int32(len(payload)))
	packet.Write(payload)
	packet.UDP = &destination
	calls := 0
	sink := testBufferWriter(func(mb buf.MultiBuffer) error {
		defer buf.ReleaseMulti(mb)
		calls++
		if len(mb) != 1 || mb[0].UDP != &destination || !bytes.Equal(mb[0].Bytes(), payload) {
			t.Fatal("rate limiting split or corrupted a large UDP datagram")
		}
		return nil
	})
	controller := NewController(12500000)
	writer := NewRateLimitWriter(sink, controller, context.Background())
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || controller.Total() != int64(len(payload)) {
		t.Fatalf("datagram calls=%d accounted=%d", calls, controller.Total())
	}
}
