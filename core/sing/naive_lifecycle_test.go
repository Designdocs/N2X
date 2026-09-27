package sing

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/counter"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"golang.org/x/net/http2"
)

func TestNaiveUserUpdatesPreserveActiveTunnel(t *testing.T) {
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	testNaiveUserUpdatesPreserveActiveTunnel(t, "tcp", transport)
}

func testNaiveUserUpdatesPreserveActiveTunnel(t *testing.T, network string, transport http.RoundTripper) {
	core := newLifecycleCore(t)
	tag := "naive-live-users"
	limiter.AddLimiter(tag, &conf.LimitConfig{}, lifecycleUsers, nil)
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	info := &panel.NodeInfo{Type: "naive", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: freePort(t)}, Naive: &panel.NaiveNode{Network: network}}
	if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err != nil {
		t.Fatal(err)
	}
	add := func(users []panel.UserInfo) {
		t.Helper()
		if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(users []panel.UserInfo) {
		t.Helper()
		if err := core.DelUsers(users, tag, info); err != nil {
			t.Fatal(err)
		}
	}
	add(lifecycleUsers)
	original, _ := core.box.Inbound().Get(tag)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "still-connected")
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	address := fmt.Sprintf("127.0.0.1:%d", info.Common.ServerPort)
	credentials := func(user panel.UserInfo) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user.Uuid+":"+user.Uuid))
	}
	upload, writer := io.Pipe()
	defer writer.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, upload)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = target.Listener.Addr().String()
	request.Header.Set("Proxy-Authorization", credentials(lifecycleUsers[0]))
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	stop := time.AfterFunc(5*time.Second, func() { writer.Close(); response.Body.Close() })
	defer stop.Stop()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	exchange := func() {
		t.Helper()
		if _, err := fmt.Fprintf(writer, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target.Listener.Addr().String()); err != nil {
			t.Fatal(err)
		}
		reply, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(reply.Body)
		reply.Body.Close()
		if err != nil || string(payload) != "still-connected" {
			t.Fatalf("payload=%q err=%v", payload, err)
		}
		traffic, err := core.GetUserTrafficSlice(tag, true)
		if err != nil {
			t.Fatal(err)
		}
		counted := false
		for _, sample := range traffic {
			if sample.UID == lifecycleUsers[0].Id && sample.Upload > 0 && sample.Download > 0 {
				counted = true
			}
		}
		if !counted {
			t.Fatal("live tunnel traffic was lost after user update")
		}
		current, _ := core.box.Inbound().Get(tag)
		if current != original {
			t.Fatal("user update replaced the inbound")
		}
	}
	checkNewRequest := func(user panel.UserInfo, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = target.Listener.Addr().String()
		req.Header.Set("Proxy-Authorization", credentials(user))
		reply, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, reply.Body)
		reply.Body.Close()
		if reply.StatusCode != want {
			t.Fatalf("new request status=%d want=%d", reply.StatusCode, want)
		}
	}
	exchange()
	remove(lifecycleUsers[:1])
	exchange()
	checkNewRequest(lifecycleUsers[0], http.StatusNotFound)
	checkNewRequest(lifecycleUsers[1], http.StatusOK)
	add(lifecycleUsers[:1])
	exchange()
	checkNewRequest(lifecycleUsers[0], http.StatusOK)
	remove(lifecycleUsers)
	exchange()
	checkNewRequest(lifecycleUsers[0], http.StatusNotFound)
	checkNewRequest(lifecycleUsers[1], http.StatusNotFound)
	add(lifecycleUsers)
	exchange()
	checkNewRequest(lifecycleUsers[0], http.StatusOK)
	remove(lifecycleUsers)
	writer.Close()
	response.Body.Close()
	for deadline := time.Now().Add(time.Second); ; {
		if _, err := core.GetUserTrafficSlice(tag, true); err != nil {
			t.Fatal(err)
		}
		value, _ := core.hookServer.counter.Load(tag)
		if value.(*counter.TrafficCounter).Len() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired user accounting was not reclaimed after tunnel closed")
		}
		time.Sleep(time.Millisecond)
	}
	if err := core.DelNode(tag); err != nil {
		t.Fatal(err)
	}
	var rebound io.Closer
	if network == "udp" {
		rebound, err = net.ListenPacket("udp", address)
	} else {
		rebound, err = net.Listen("tcp", address)
	}
	if err != nil {
		t.Fatalf("node close did not release listener: %v", err)
	}
	rebound.Close()
}

func TestNaiveInitialFailureDoesNotCommitUsers(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "naive-retry"
	info := &panel.NodeInfo{Type: "naive", Common: &panel.CommonNode{ServerPort: freePort(t)}, Naive: &panel.NaiveNode{Network: "tcp"}}
	if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
		t.Fatal(err)
	}
	params := &vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info}
	if _, err := core.AddUsers(params); err == nil {
		t.Fatal("missing TLS certificate was accepted")
	}
	node := core.naive.nodes[tag]
	if len(node.users) != 0 || node.built {
		t.Fatal("failed creation committed user state")
	}
	node.options = lifecycleOptions(t, true)
	info.Security = panel.Tls
	if _, err := core.AddUsers(params); err != nil {
		t.Fatalf("retry of same users: %v", err)
	}
	if err := core.DelNode(tag); err != nil {
		t.Fatal(err)
	}
}

func TestNaiveRetiresUsersWithoutTraffic(t *testing.T) {
	core := newLifecycleCore(t)
	tag := "naive-empty-accounting"
	info := &panel.NodeInfo{Type: "naive", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: freePort(t)}, Naive: &panel.NaiveNode{Network: "tcp"}}
	if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	// Keep the UID as an authenticated request awaiting routing would do.
	// No storage is ever created if that request fails before routing.
	if err := core.delNaiveUsers(tag, lifecycleUsers); err != nil {
		t.Fatal(err)
	}
	if _, err := core.GetUserTrafficSlice(tag, true); err != nil {
		t.Fatal(err)
	}
	if len(core.naive.nodes[tag].retired) != 0 || len(core.users.uidMap) != 0 {
		t.Fatal("retired users without traffic were retained")
	}
	if err := core.DelNode(tag); err != nil {
		t.Fatal(err)
	}
}
