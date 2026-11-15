package rate

import (
	"context"
	"io"
	"net"
	"testing"
)

func BenchmarkConnUnlimited(b *testing.B) {
	for _, managed := range []bool{false, true} {
		name := "raw"
		if managed {
			name = "managed"
		}
		b.Run(name, func(b *testing.B) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			go func() { _, _ = io.Copy(io.Discard, server) }()
			var writer io.Writer = client
			if managed {
				wrapped := NewConnRateLimiter(client, NewController(0), context.Background())
				defer wrapped.Close()
				writer = wrapped
			}
			payload := make([]byte, 32768)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				if n, err := writer.Write(payload); err != nil || n != len(payload) {
					b.Fatalf("write=%d %v", n, err)
				}
			}
		})
	}
}
