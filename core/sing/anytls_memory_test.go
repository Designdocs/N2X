package sing

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
)

func TestAnyTLSNodeRemovalClosesPendingConnections(t *testing.T) {
	for _, phase := range []string{"TLS handshake", "authentication"} {
		t.Run(phase, func(t *testing.T) {
			core := newLifecycleCore(t)
			info := &panel.NodeInfo{
				Type:     "anytls",
				Security: panel.Tls,
				Common:   &panel.CommonNode{ServerPort: freePort(t)},
				AnyTls:   &panel.AnyTlsNode{},
			}
			if err := core.AddNode("anytls-memory", info, lifecycleOptions(t, true)); err != nil {
				t.Fatal(err)
			}
			address := fmt.Sprintf("127.0.0.1:%d", info.Common.ServerPort)
			dialer := &net.Dialer{Timeout: time.Second}
			var conn net.Conn
			var err error
			if phase == "authentication" {
				conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true}) // Local test certificate.
			} else {
				conn, err = dialer.Dial("tcp", address)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := core.DelNode("anytls-memory"); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			_, err = conn.Read(data[:])
			var timeout net.Error
			if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
				t.Fatalf("pending %s connection survived node removal: %v", phase, err)
			}
		})
	}
}

type pausedAnyTLSSYNConn struct {
	net.Conn
	read   chan struct{}
	resume chan struct{}
}

func (c *pausedAnyTLSSYNConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n == 7 && p[0] == 1 {
		close(c.read)
		<-c.resume
	}
	return n, err
}

func TestAnyTLSShutdownClosesLateStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		in, err := anytls.NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "late-stream", option.AnyTLSInboundOptions{
			Users: []option.AnyTLSUser{{Name: "test-user", Password: "test-password"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		server, client := net.Pipe()
		conn := &pausedAnyTLSSYNConn{Conn: server, read: make(chan struct{}), resume: make(chan struct{})}
		t.Cleanup(func() { _ = client.Close(); _ = in.(*anytls.Inbound).Close() })
		done := make(chan struct{})
		go func() {
			in.(*anytls.Inbound).NewConnectionEx(context.Background(), conn, adapter.InboundContext{}, nil)
			close(done)
		}()
		write := func(data []byte) {
			if _, err := client.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		password := sha256.Sum256([]byte("test-password"))
		write(append(password[:], 0, 0))
		settings := []byte("v=1\npadding-md5=" + padding.NewPaddingFactory(padding.DefaultPaddingScheme).Md5)
		header := []byte{4, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(header[5:], uint16(len(settings)))
		write(append(header, settings...))
		write([]byte{1, 0, 0, 0, 1, 0, 0})
		<-conn.read
		if err := in.(*anytls.Inbound).Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		close(conn.resume)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("closed inbound's session did not exit")
		}
	})
}
