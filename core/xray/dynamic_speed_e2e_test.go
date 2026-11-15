package xray

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/common/counter"
	"github.com/Designdocs/N2X/common/format"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/limiter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// The same authenticated stream must survive unlimited -> penalized ->
// released. Synthetic clock/counter observations avoid a three-minute sleep;
// speed enforcement and billing use real local sockets and a public mux client.
func TestDynamicSpeedExistingXrayMuxStreamAndAccounting(t *testing.T) {
	tag := t.Name()
	core, address := startTrojanNode(t, tag, &panel.MultiplexSettings{Enabled: true}, 0)
	client := newSingMuxClient(t, address, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr(startTCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	echo := func(payload []byte) {
		t.Helper()
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, reply) {
			t.Fatal("echo body changed")
		}
	}
	echo([]byte("warmup"))
	l, err := limiter.GetLimiter(tag)
	if err != nil {
		t.Fatal(err)
	}
	b, reject := l.CheckLimit(format.UserTag(tag, singMuxTestPassword), "127.0.0.1", true, true)
	if reject {
		t.Fatal("authenticated identity rejected")
	}
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 2, SustainSeconds: 30, LimitMbps: 1, PenaltySeconds: 60}
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 6 {
		b.Account(3 * 1000000 / 8 * 5)
		now = now.Add(5 * time.Second)
		l.SampleDynamic(now)
	}
	status := l.DynamicSpeedStatus()
	if status.LimitedUsers != 1 {
		t.Fatalf("no penalty: %+v", status)
	}
	payload := bytes.Repeat([]byte("speed"), 13108) // 65540 bytes each way
	start := time.Now()
	echo(payload)
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("old stream bypassed aggregate cap: %v", elapsed)
	}
	command := conf.DynamicSpeedCommand{ID: "release-existing", PenaltyID: status.Penalties[0].ID, UserID: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := l.ConfigureDynamic(p, []conf.DynamicSpeedCommand{command}, ""); err != nil {
		t.Fatal(err)
	}
	if b.Rate() != 0 {
		t.Fatal("old stream retained penalty after release")
	}
	echo(payload)
	traffic, err := core.GetUserTrafficSlice(tag, true)
	if err != nil {
		t.Fatal(err)
	}
	var up, down int64
	for _, entry := range traffic {
		if entry.UID != 1 {
			t.Fatal("traffic attributed to another user")
		}
		up += entry.Upload
		down += entry.Download
	}
	want := int64(6 + 2*len(payload))
	if up != want || down != want {
		t.Fatalf("billing up/down=%d/%d want=%d (synthetic detector observations must not be billed)", up, down, want)
	}
}

func TestDynamicSpeedConcurrentXrayBillingDrainsDoNotLoseBytes(t *testing.T) {
	tag := t.Name()
	core, _ := startTrojanNode(t, tag, nil, 0)
	trafficCounter := counter.NewTrafficCounter()
	core.dispatcher.Counter.Store(tag, trafficCounter)
	storage := trafficCounter.GetCounter(format.UserTag(tag, singMuxTestPassword))
	done := make(chan struct{})
	go func() {
		for range 100000 {
			storage.UpCounter.Add(1)
			storage.DownCounter.Add(2)
		}
		close(done)
	}()
	var up, down int64
	for {
		traffic, err := core.GetUserTrafficSlice(tag, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range traffic {
			up += entry.Upload
			down += entry.Download
		}
		select {
		case <-done:
			up += storage.UpCounter.Swap(0)
			down += storage.DownCounter.Swap(0)
			if up != 100000 || down != 200000 {
				t.Fatalf("billing lost bytes: %d/%d", up, down)
			}
			return
		default:
			runtime.Gosched()
		}
	}
}

// DispatchLink is used by raw VLESS and several datagram inbounds. Its upload
// path is a reader, unlike Dispatch's pair of writers; both must share the cap.
func TestDynamicSpeedDispatchLinkSharesUploadAndDownloadBudget(t *testing.T) {
	tag := t.Name()
	core, _ := startTrojanNode(t, tag, nil, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag: tag, User: &protocol.MemoryUser{Email: format.UserTag(tag, singMuxTestPassword)},
		Source: xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 1234),
	})
	destination, err := xnet.ParseDestination("tcp:" + startTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	upReader, upWriter := pipe.New()
	downReader, downWriter := pipe.New()
	defer common.Interrupt(upReader)
	defer common.Interrupt(downReader)
	done := make(chan error, 1)
	go func() {
		done <- core.dispatcher.DispatchLink(ctx, destination, &transport.Link{Reader: upReader, Writer: downWriter})
	}()
	reader := &buf.BufferedReader{Reader: downReader}
	echo := func(payload []byte) {
		t.Helper()
		if err := upWriter.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, reply) {
			t.Fatal("direct link changed payload")
		}
	}
	echo([]byte("warmup"))
	l, err := limiter.GetLimiter(tag)
	if err != nil {
		t.Fatal(err)
	}
	b, reject := l.CheckLimit(format.UserTag(tag, singMuxTestPassword), "127.0.0.1", true, true)
	if reject {
		t.Fatal("direct link user rejected")
	}
	p := &conf.NodeDynamicSpeedPolicy{Version: 2, OverThresholdPercent: 85, Revision: 1, Enabled: true, ThresholdMbps: 2, SustainSeconds: 30, LimitMbps: 1, PenaltySeconds: 60}
	if err := l.ConfigureDynamic(p, nil, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 6 {
		b.Account(3 * 1000000 / 8 * 5)
		now = now.Add(5 * time.Second)
		l.SampleDynamic(now)
	}
	before := b.Total()
	payload := bytes.Repeat([]byte("a"), 65536)
	start := time.Now()
	echo(payload)
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("direct link upload escaped the combined speed cap: %v", elapsed)
	}
	if got, want := b.Total()-before, int64(2*len(payload)); got != want {
		t.Fatalf("direct link observed bytes=%d want=%d", got, want)
	}
	traffic, err := core.GetUserTrafficSlice(tag, true)
	if err != nil {
		t.Fatal(err)
	}
	var up, down int64
	for _, entry := range traffic {
		up += entry.Upload
		down += entry.Download
	}
	if want := int64(6 + len(payload)); up != want || down != want {
		t.Fatalf("direct link billing=%d/%d want=%d", up, down, want)
	}
	common.Close(upWriter)
	cancel()
	common.Interrupt(upReader)
	common.Interrupt(downReader)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct link did not finish after cancellation")
	}
}
