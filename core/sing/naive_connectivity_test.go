package sing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"golang.org/x/net/http2"
)

// This independent wire reader covers the first eight Naive padded frames and
// the subsequent raw stream, rather than using the inbound's private codec.
type naiveWireReader struct {
	source                io.Reader
	frames, data, padding int
}

func (r *naiveWireReader) Read(p []byte) (int, error) {
	for r.data == 0 {
		if r.padding > 0 {
			if _, err := io.CopyN(io.Discard, r.source, int64(r.padding)); err != nil {
				return 0, err
			}
			r.padding = 0
		}
		if r.frames >= 8 {
			return r.source.Read(p)
		}
		var h [3]byte
		if _, err := io.ReadFull(r.source, h[:]); err != nil {
			return 0, err
		}
		r.data = int(binary.BigEndian.Uint16(h[:2]))
		r.padding = int(h[2])
		r.frames++
	}
	if len(p) > r.data {
		p = p[:r.data]
	}
	n, err := r.source.Read(p)
	r.data -= n
	return n, err
}

func TestSingNaiveRealTLSBrowserAndPaddedHTTP2(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "naive-real-wire"
	users := append([]panel.UserInfo(nil), lifecycleUsers...)
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	info := &panel.NodeInfo{Type: "naive", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: freePort(t)}, Naive: &panel.NaiveNode{Network: "tcp"}}
	opts := lifecycleOptions(t, true)
	if err := core.AddNode(tag, info, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, NodeInfo: info, Users: users}); err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(opts.CertConfig.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid fixture certificate")
	}
	address := fmt.Sprintf("127.0.0.1:%d", info.Common.ServerPort)
	target := startEchoServer(t)
	auth := func(user string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+user)) }
	browserH1 := func(t *testing.T, user string, want int) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: "n2x.test", NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", target, target, auth(user)); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("HTTP/1.1 CONNECT status=%d, want %d", response.StatusCode, want)
		}
		if want != 200 {
			return
		}
		if response.Header.Get("Padding") != "" {
			t.Fatal("browser client received native padding")
		}
		payload := bytes.Repeat([]byte("browser-tunnel"), 128)
		if _, err = conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(reader, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, reply) {
			t.Fatal("browser tunnel echo mismatch")
		}
	}
	h2 := func(t *testing.T, user string, padded bool, want int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		transport := &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "n2x.test"}}
		defer transport.CloseIdleConnections()
		upload, writer := io.Pipe()
		defer upload.Close()
		defer writer.Close()
		request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, upload)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = target
		request.Header.Set("Proxy-Authorization", auth(user))
		if padded {
			request.Header.Set("Padding", "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			if want != 200 {
				return
			}
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("HTTP/2 CONNECT status=%d, want %d", response.StatusCode, want)
		}
		if want != 200 {
			return
		}
		if response.ProtoMajor != 2 {
			t.Fatal("did not negotiate HTTP/2")
		}
		if padded != (response.Header.Get("Padding") != "") {
			t.Fatal("native padding negotiation mismatch")
		}
		var reader io.Reader = response.Body
		if padded {
			reader = &naiveWireReader{source: reader}
		}
		for i := range 10 {
			payload := bytes.Repeat([]byte{byte('a' + i)}, 256)
			data := payload
			if padded && i < 8 {
				data = make([]byte, 3+len(payload)+7)
				binary.BigEndian.PutUint16(data[:2], uint16(len(payload)))
				data[2] = 7
				copy(data[3:], payload)
			}
			if _, err = writer.Write(data); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(reader, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reply, payload) {
				t.Fatalf("HTTP/2 echo mismatch at frame %d", i)
			}
		}
	}
	t.Run("browser-HTTP1", func(t *testing.T) { browserH1(t, users[0].Uuid, 200) })
	t.Run("browser-HTTP2", func(t *testing.T) { h2(t, users[0].Uuid, false, 200) })
	t.Run("native-padded-HTTP2", func(t *testing.T) { h2(t, users[0].Uuid, true, 200) })
	t.Run("wrong-credentials", func(t *testing.T) { browserH1(t, "invalid", 404); h2(t, "invalid", false, 404) })
	traffic, err := core.GetUserTrafficSlice(tag, false)
	if err != nil {
		t.Fatal(err)
	}
	counted := false
	for _, entry := range traffic {
		if entry.UID == users[0].Id && entry.Upload > 0 && entry.Download > 0 {
			counted = true
		}
	}
	if !counted {
		t.Fatalf("Naive traffic lost user identity: %+v", traffic)
	}
	if err = core.DelUsers(users[:1], tag, info); err != nil {
		t.Fatal(err)
	}
	t.Run("remaining-user-after-rebuild", func(t *testing.T) { h2(t, users[1].Uuid, true, 200) })
	t.Run("removed-user-rejected", func(t *testing.T) { browserH1(t, users[0].Uuid, 404) })
	if _, err = core.AddUsers(&vCore.AddUsersParams{Tag: tag, NodeInfo: info, Users: users[:1]}); err != nil {
		t.Fatal(err)
	}
	t.Run("restored-user-after-rebuild", func(t *testing.T) { h2(t, users[0].Uuid, true, 200) })
}
