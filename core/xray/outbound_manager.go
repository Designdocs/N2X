package xray

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/app/proxyman"
	xoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

// The upstream manager continues to own outbounds added by panel nodes.
// All readers use a single published view of those and the custom outbounds.
type outboundManager struct {
	dynamic  *xoutbound.Manager
	mu       sync.Mutex
	custom   []customOutbound
	view     atomic.Pointer[outboundView]
	retiring sync.Map
}

type outboundView struct {
	defaultHandler outbound.Handler
	byTag          map[string]outbound.Handler
	all            []outbound.Handler
	tags           []string
	selections     sync.Map
}

type customOutbound struct {
	key     string
	handler outbound.Handler
}

func newOutboundManager(ctx context.Context) (*outboundManager, error) {
	dynamic, err := xoutbound.New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		return nil, err
	}
	m := &outboundManager{dynamic: dynamic}
	m.publish(nil)
	return m, nil
}

func (*outboundManager) Type() any { return outbound.ManagerType() }

func (m *outboundManager) GetHandler(tag string) outbound.Handler { return m.view.Load().byTag[tag] }
func (m *outboundManager) GetDefaultHandler() outbound.Handler    { return m.view.Load().defaultHandler }

func (m *outboundManager) ListHandlers(context.Context) []outbound.Handler {
	return slices.Clone(m.view.Load().all)
}

func (m *outboundManager) Select(selectors []string) []string {
	view := m.view.Load()
	key := strings.Join(selectors, ",")
	if cached, ok := view.selections.Load(key); ok {
		return cached.([]string)
	}
	tags := make([]string, 0, len(selectors))
	for _, tag := range view.tags {
		for _, prefix := range selectors {
			if strings.HasPrefix(tag, prefix) {
				tags = append(tags, tag)
				break
			}
		}
	}
	view.selections.Store(key, tags)
	return tags
}

func (m *outboundManager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tag := handler.Tag(); tag != "" && m.GetHandler(tag) != nil {
		return fmt.Errorf("existing tag found: %s", tag)
	}
	if err := m.dynamic.AddHandler(ctx, handler); err != nil {
		return err
	}
	m.publish(m.custom)
	return nil
}

func (m *outboundManager) RemoveHandler(ctx context.Context, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.dynamic.RemoveHandler(ctx, tag); err != nil {
		return err
	}
	m.publish(m.custom)
	return nil
}

func (m *outboundManager) Start() error {
	for _, entry := range m.custom {
		if err := entry.handler.Start(); err != nil {
			return err
		}
	}
	return m.dynamic.Start()
}

func (m *outboundManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, entry := range m.custom {
		errs = append(errs, entry.handler.Close())
	}
	m.retiring.Range(func(handler, _ any) bool {
		errs = append(errs, handler.(*outboundGeneration).Close())
		return true
	})
	m.view.Store(&outboundView{})
	return errors.Join(append(errs, m.dynamic.Close())...)
}

// publish runs with mutations serialized. Readers never wait for file parsing
// or handler construction. A new view also invalidates the selector cache.
func (m *outboundManager) publish(custom []customOutbound) {
	dynamic := m.dynamic.ListHandlers(context.Background())
	view := &outboundView{
		defaultHandler: m.dynamic.GetDefaultHandler(),
		byTag:          make(map[string]outbound.Handler, len(custom)+len(dynamic)),
		all:            make([]outbound.Handler, 0, len(custom)+len(dynamic)),
	}
	if len(custom) > 0 {
		view.defaultHandler = custom[0].handler
		if generation, ok := view.defaultHandler.(*outboundGeneration); ok {
			view.defaultHandler = defaultOutbound{generation}
		}
	}
	for _, entry := range custom {
		view.all = append(view.all, entry.handler)
	}
	view.all = append(view.all, dynamic...)
	for _, handler := range view.all {
		if tag := handler.Tag(); tag != "" {
			view.byTag[tag] = handler
			view.tags = append(view.tags, tag)
		}
	}
	slices.Sort(view.tags)
	m.custom = custom
	m.view.Store(view)
}

// A generation is retained for the entire synchronous Dispatch call. Only
// outbounds with a synchronous connection lifetime use this wrapper.
type outboundGeneration struct {
	outbound.Handler
	owner     *outboundManager
	refs      atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

const outboundRetired = 1 << 62

// A dispatch using the default must still follow the new default if its
// lookup preceded the swap and the former first outbound was removed.
type defaultOutbound struct{ *outboundGeneration }

func (g defaultOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	g.dispatch(ctx, link, true)
}

func (g *outboundGeneration) GetOutbound() proxy.Outbound {
	if handler, ok := g.Handler.(proxy.GetOutbound); ok {
		return handler.GetOutbound()
	}
	return nil
}

func (g *outboundGeneration) acquire() bool {
	if g.refs.Add(1) < outboundRetired {
		return true
	}
	g.release()
	return false
}

func (g *outboundGeneration) Dispatch(ctx context.Context, link *transport.Link) {
	g.dispatch(ctx, link, false)
}

func (g *outboundGeneration) dispatch(ctx context.Context, link *transport.Link, useDefault bool) {
	for {
		if g.acquire() {
			g.dispatchHeld(ctx, link)
			return
		}
		// A lookup may race with publication. Never dispatch to a handler
		// that has already been retired.
		next := g.owner.GetHandler(g.Tag())
		if useDefault {
			next = g.owner.GetDefaultHandler()
			if current, ok := next.(defaultOutbound); ok {
				next = current.outboundGeneration
			}
		}
		if next == nil || next == g {
			_ = common.Close(link.Writer)
			_ = common.Interrupt(link.Reader)
			return
		}
		generation, ok := next.(*outboundGeneration)
		if !ok {
			next.Dispatch(ctx, link)
			return
		}
		g = generation
	}
}

func (g *outboundGeneration) dispatchHeld(ctx context.Context, link *transport.Link) {
	defer g.release()
	g.Handler.Dispatch(ctx, link)
}

func (g *outboundGeneration) release() {
	if g.refs.Add(-1) == outboundRetired {
		_ = g.Close()
	}
}

func (g *outboundGeneration) retire() {
	g.owner.retiring.Store(g, struct{}{})
	if g.refs.Add(outboundRetired) == outboundRetired {
		_ = g.Close()
	}
}

func (g *outboundGeneration) Close() error {
	g.closeOnce.Do(func() {
		g.closeErr = g.Handler.Close()
		g.owner.retiring.Delete(g)
	})
	return g.closeErr
}
