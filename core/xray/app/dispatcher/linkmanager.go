package dispatcher

import (
	"context"
	"sync"

	"github.com/Designdocs/N2X/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
	onClose func()
}

func (w *ManagedWriter) trackOnline(ctx context.Context, l *limiter.Limiter, tagUUID, ip string) {
	release := l.TrackConnection(tagUUID, ip)
	stop := context.AfterFunc(ctx, release)
	w.onClose = func() {
		stop()
		release()
	}
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	if w.onClose != nil {
		w.onClose()
	}
	return common.Close(w.writer)
}

func (w *ManagedWriter) Interrupt() {
	w.manager.RemoveWriter(w)
	if w.onClose != nil {
		w.onClose()
	}
	common.Interrupt(w.writer)
}

type LinkManager struct {
	links map[*ManagedWriter]buf.Reader
	mu    sync.Mutex
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[writer] = reader
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	links := make(map[*ManagedWriter]buf.Reader, len(m.links))
	for w, r := range m.links {
		links[w] = r
	}
	m.mu.Unlock()
	for w, r := range links {
		common.Close(w)
		common.Interrupt(r)
	}
}
