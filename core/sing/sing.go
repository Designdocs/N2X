package sing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/Designdocs/N2X/common/porthop"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

var _ vCore.Core = (*Sing)(nil)

func init() {
	vCore.RegisterCore("sing", New)
}

// Sing wraps a sing-box instance and drives it from the panel: nodes become
// inbounds, panel users become inbound users, and every routed connection is
// wrapped by the hook server for rate limiting and traffic accounting.
type Sing struct {
	box        *box.Box
	ctx        context.Context
	hookServer *HookServer
	router     adapter.Router
	logFactory log.Factory

	users                     *UserMap
	nodeReportMinTrafficBytes map[string]int64
	reportMu                  sync.RWMutex

	// nodeTypes remembers the panel node type behind each tag so DelNode can
	// tear down the extra inbounds a composite protocol created.
	nodeTypes sync.Map // tag -> string

	// detourOwners maps an internal detour inbound tag back to the node tag
	// that owns it, so limits and traffic land on the node (see hook.go).
	detourOwners sync.Map // detour tag -> node tag

	// naive owns the rebuild-based user management NaiveProxy needs.
	naive *naiveState

	// portHop owns the firewall redirects that back Hysteria port hopping,
	// so they are removed with the node rather than left on the host.
	portHop *porthop.Manager
}

// UserMap translates the per-inbound user identity sing-box reports back into
// the panel user id the traffic report is keyed by.
type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	if c.SingConfig == nil {
		c.SingConfig = conf.NewSingConfig()
	}
	ctx := context.Background()
	ctx = box.Context(ctx,
		inboundRegistry(),
		outboundRegistry(),
		endpointRegistry(),
		dnsTransportRegistry(),
		serviceRegistry(),
	)

	options := option.Options{}
	if len(c.SingConfig.OriginalPath) != 0 {
		data, err := os.ReadFile(c.SingConfig.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("read original config error: %w", err)
		}
		options, err = json.UnmarshalExtendedContext[option.Options](ctx, data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal original config error: %w", err)
		}
	}
	options.Log = &option.LogOptions{
		Disabled:  c.SingConfig.LogConfig.Disabled,
		Level:     c.SingConfig.LogConfig.Level,
		Timestamp: c.SingConfig.LogConfig.Timestamp,
		Output:    c.SingConfig.LogConfig.Output,
	}
	options.NTP = &option.NTPOptions{
		Enabled:       c.SingConfig.NtpConfig.Enable,
		WriteToSystem: true,
		ServerOptions: option.ServerOptions{
			Server:     c.SingConfig.NtpConfig.Server,
			ServerPort: c.SingConfig.NtpConfig.ServerPort,
		},
	}

	b, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, fmt.Errorf("create sing-box instance error: %w", err)
	}
	hs := newHookServer()
	b.Router().AppendTracker(hs)
	s := &Sing{
		ctx:        b.Router().GetCtx(),
		box:        b,
		hookServer: hs,
		router:     b.Router(),
		logFactory: b.LogFactory(),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		nodeReportMinTrafficBytes: make(map[string]int64),
		naive:                     newNaiveState(),
		portHop:                   porthop.NewManager(),
	}
	hs.resolveTag = s.resolveNodeTag
	return s, nil
}

// resolveNodeTag maps a sing-box inbound tag to the panel node tag that owns
// it. Only composite protocols introduce extra inbounds; every other tag is
// already a node tag.
func (b *Sing) resolveNodeTag(inboundTag string) string {
	if owner, ok := b.detourOwners.Load(inboundTag); ok {
		return owner.(string)
	}
	return inboundTag
}

func (b *Sing) Start() error {
	return b.box.Start()
}

func (b *Sing) Close() error {
	// The firewall outlives this process, so its rules go first.
	return errors.Join(b.portHop.RemoveAll(), b.box.Close())
}

// Protocols lists the panel node types this core can serve.
//
// Several of these overlap with the xray core on purpose — anytls in
// particular is deliberately served by both cores. When more than one core is
// configured, core/selector.go resolves the overlap; pin a node explicitly
// with the "Core" or "CoreName" option to choose.
//
// QUIC-based types are only advertised when the binary was built with the
// with_quic tag, so the selector never routes a node to a core that cannot
// actually listen for it.
func (b *Sing) Protocols() []string {
	protocols := []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
		"anytls",
		"shadowtls",
		"naive",
	}
	return append(protocols, quicProtocols...)
}

func (b *Sing) Type() string {
	return "sing"
}

// reportMinTraffic returns the per-node reporting threshold in bytes.
func (b *Sing) reportMinTraffic(tag string) int64 {
	b.reportMu.RLock()
	defer b.reportMu.RUnlock()
	return b.nodeReportMinTrafficBytes[tag]
}

func (b *Sing) setReportMinTraffic(tag string, bytes int64) {
	b.reportMu.Lock()
	defer b.reportMu.Unlock()
	b.nodeReportMinTrafficBytes[tag] = bytes
}

func (b *Sing) deleteReportMinTraffic(tag string) {
	b.reportMu.Lock()
	defer b.reportMu.Unlock()
	delete(b.nodeReportMinTrafficBytes, tag)
}
