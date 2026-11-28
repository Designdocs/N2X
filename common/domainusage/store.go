// Package domainusage keeps completed hourly snapshots on the node, grouped by UTC day.
package domainusage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Key struct {
	UID  int
	Host string
}
type Flow struct {
	Bytes  atomic.Int64
	refs   int
	starts int64
}
type Row struct {
	Host        string  `json:"host"`
	Raw         int64   `json:"raw"`
	Weighted    float64 `json:"weighted"`
	Connections int64   `json:"connections"`
}

func (r *Row) add(v Row) {
	r.Raw += v.Raw
	r.Weighted += v.Weighted
	r.Connections += v.Connections
}

const maxTrackedKeys = 32768

var trackedKeys atomic.Int64

type Store struct {
	files      files
	ctx        context.Context
	cancel     context.CancelFunc
	memoryFull atomic.Bool
	billingMu  sync.Mutex
	ioMu       sync.Mutex
	flowsMu    sync.Mutex
	flows      map[Key]*Flow
	mu         sync.Mutex
	pending    map[string]map[Key]Row
	rate       float64
	closed     bool
}

func Open(path string, rate float64) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Store{files: files{path, MaxDiskBytes, MinFreeBytes, FreeBytes}, ctx: ctx, cancel: cancel, flows: make(map[Key]*Flow), pending: make(map[string]map[Key]Row), rate: rate}, nil
}
func (s *Store) Context() context.Context { return s.ctx }
func (s *Store) MemoryFull() bool         { return s.memoryFull.Load() }
func cleanHost(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return s
}
func (s *Store) Track(uid int, host string) (*Flow, func()) {
	k := Key{uid, cleanHost(host)}
	s.flowsMu.Lock()
	if s.ctx.Err() != nil || s.memoryFull.Load() {
		s.flowsMu.Unlock()
		return nil, nil
	}
	f := s.flows[k]
	if f == nil {
		if trackedKeys.Add(1) > maxTrackedKeys {
			trackedKeys.Add(-1)
			s.memoryFull.Store(true)
			s.flowsMu.Unlock()
			return nil, nil
		}
		f = &Flow{}
		s.flows[k] = f
	}
	f.refs++
	f.starts++
	s.flowsMu.Unlock()
	return f, sync.OnceFunc(func() { s.flowsMu.Lock(); f.refs--; s.flowsMu.Unlock() })
}

// The forwarding path only increments an atomic counter. Sampling a billing
// interval can split rates without writing that interval into the database.
func (s *Store) drain() map[Key]Row {
	s.flowsMu.Lock()
	defer s.flowsMu.Unlock()
	rows := make(map[Key]Row)
	for k, f := range s.flows {
		raw := f.Bytes.Swap(0)
		if raw != 0 || f.starts != 0 {
			rows[k] = Row{Raw: raw, Connections: f.starts}
			f.starts = 0
		}

	}
	return rows
}
func (s *Store) merge(at time.Time, batch map[Key]Row, rate float64) {
	if len(batch) == 0 {
		return
	}
	day := at.UTC().Format(time.DateOnly)
	rows := s.pending[day]
	if rows == nil {
		rows = make(map[Key]Row)
		s.pending[day] = rows
	}
	for k, delta := range batch {
		delta.Weighted = float64(delta.Raw) * rate
		r := rows[k]
		r.add(delta)
		rows[k] = r
	}
}

// Capture before the HTTP request. Bytes arriving during a slow response must
// stay in the next billing interval.
func (s *Store) StartBilling(at time.Time) func(*float64) {
	s.billingMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.billingMu.Unlock()
		return func(*float64) {}
	}
	fallback := s.rate
	batch := s.drain()
	s.mu.Unlock()
	return func(actual *float64) {
		s.mu.Lock()
		rate := fallback
		if actual != nil {
			rate = *actual
		}
		s.merge(at, batch, rate)
		s.mu.Unlock()
		s.billingMu.Unlock()
	}
}
func (s *Store) SetRate(at time.Time, rate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && rate != s.rate {
		s.merge(at, s.drain(), s.rate)
		s.rate = rate
	}
}
func decode(b []byte) Row {
	if len(b) != 24 {
		return Row{}
	}
	return Row{Raw: int64(binary.BigEndian.Uint64(b)), Weighted: math.Float64frombits(binary.BigEndian.Uint64(b[8:])), Connections: int64(binary.BigEndian.Uint64(b[16:]))}
}
func encode(r Row) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint64(b, uint64(r.Raw))
	binary.BigEndian.PutUint64(b[8:], math.Float64bits(r.Weighted))
	binary.BigEndian.PutUint64(b[16:], uint64(r.Connections))
	return b
}

// Swap the hourly buffer before taking the machine-wide file lock. Ordinary
// accounting can continue while a query or another controller holds that lock.
func (s *Store) snapshot(at time.Time, closing bool) map[string]map[Key]Row {
	s.billingMu.Lock()
	defer s.billingMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = closing
	s.merge(at, s.drain(), s.rate)
	batch := s.pending
	s.pending = make(map[string]map[Key]Row)
	s.flowsMu.Lock()
	for k, f := range s.flows {
		if closing || f.refs == 0 && f.starts == 0 && f.Bytes.Load() == 0 {
			delete(s.flows, k)
			trackedKeys.Add(-1)
		}
	}
	s.flowsMu.Unlock()
	return batch
}
func (s *Store) write(batch map[string]map[Key]Row, at, through time.Time) error {
	unlock, err := s.files.lock(true)
	if err != nil {
		return err
	}
	defer unlock()
	cutoff := through.UTC().AddDate(0, 0, -29).Format(time.DateOnly)
	last := at.UTC().Format(time.DateOnly)
	if batch[last] == nil {
		batch[last] = make(map[Key]Row)
	}
	days := make([]string, 0, len(batch))
	for day := range batch {
		if day < cutoff {
			delete(batch, day)
		} else {
			days = append(days, day)
		}
	}
	sort.Strings(days)
	for _, day := range days {
		if err := s.files.writeDay(day, through, batch[day]); err != nil {
			return err
		}
		delete(batch, day)
	}
	return nil
}
func (s *Store) Flush(at time.Time) error      { return s.flushWindow(at, at) }
func (s *Store) FlushHour(end time.Time) error { return s.flushWindow(end.Add(-time.Nanosecond), end) }
func (s *Store) flushWindow(at, through time.Time) error {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	batch := s.snapshot(at, false)
	if batch == nil {
		return nil
	}
	err := s.write(batch, at, through)
	if err != nil {
		s.mu.Lock()
		for day, remaining := range batch {
			if s.pending[day] == nil {
				s.pending[day] = remaining
				continue
			}
			for k, delta := range remaining {
				r := s.pending[day][k]
				r.add(delta)
				s.pending[day][k] = r
			}
		}
		s.mu.Unlock()
	}
	return err
}
func (s *Store) Close(at time.Time) error {
	s.cancel()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	batch := s.snapshot(at, true)
	if batch == nil {
		return nil
	}
	return s.write(batch, at, at)
}

// Pause cancels work and discards uncommitted statistics without writing to disk.
func (s *Store) Pause() {
	s.cancel()
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.billingMu.Lock()
	defer s.billingMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	clear(s.pending)
	s.flowsMu.Lock()
	trackedKeys.Add(-int64(len(s.flows)))
	s.flows = nil
	s.flowsMu.Unlock()
}

const PageSize = 300

var ErrSnapshotChanged = errors.New("domain usage changed during report")

type Page struct {
	Rows    []Row
	Until   int64
	Version string
	More    bool
}

func (s *Store) QueryPage(uid int, day time.Time, after *string) (Page, error) {
	return s.queryPage(uid, day, after, nil)
}

// LivePages includes pending counters for one user without resetting counters or
// writing an extra hourly batch. Freeze them alongside the first disk page so
// an hourly flush cannot move those bytes to disk between the two reads.
func (s *Store) LivePages(uid int, now time.Time) func(*string) (Page, error) {
	var rows []Row
	return func(after *string) (Page, error) {
		if after == nil {
			s.ioMu.Lock()
			defer s.ioMu.Unlock()
			rows = s.liveRows(uid, now)
		}
		page, err := s.queryPage(uid, now, after, rows)
		page.Until = now.Unix()
		return page, err
	}
}

func (s *Store) liveRows(uid int, now time.Time) []Row {
	// A pending billing response can still supply the rate for its interval.
	s.billingMu.Lock()
	s.mu.Lock()
	totals := make(map[string]Row)
	add := func(host string, delta Row) {
		r := totals[host]
		r.Host = host
		r.add(delta)
		totals[host] = r
	}
	cutoff := now.UTC().AddDate(0, 0, -29).Format(time.DateOnly)
	for date, batch := range s.pending {
		if date < cutoff || date > now.UTC().Format(time.DateOnly) {
			continue
		}
		for k, r := range batch {
			if k.UID == uid {
				add(k.Host, r)
			}
		}
	}
	s.flowsMu.Lock()
	for k, flow := range s.flows {
		if k.UID == uid {
			raw := flow.Bytes.Load()
			if raw != 0 || flow.starts != 0 {
				add(k.Host, Row{Raw: raw, Weighted: float64(raw) * s.rate, Connections: flow.starts})
			}
		}
	}
	s.flowsMu.Unlock()
	s.mu.Unlock()
	s.billingMu.Unlock()
	rows := make([]Row, 0, len(totals))
	for _, row := range totals {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Host < rows[j].Host })
	return rows
}

func (s *Store) queryPage(uid int, day time.Time, after *string, live []Row) (Page, error) {
	var page Page
	totals := make(map[string]Row)
	start := 0
	if after != nil {
		start = sort.Search(len(live), func(i int) bool { return live[i].Host > *after })
	}
	for _, r := range live[start:min(len(live), start+PageSize+1)] {
		totals[r.Host] = r
	}
	version := sha256.New()
	unlock, err := s.files.lock(false)
	if err != nil {
		return page, err
	}
	defer unlock()
	var days []string
	for i := 0; i < 30; i++ {
		if err := s.ctx.Err(); err != nil {
			return page, err
		}
		d := day.UTC().AddDate(0, 0, -i).Format(time.DateOnly)
		days = append(days, d)
		if err := s.files.read(s.files.dayPath(d), []string{d}, uid, after, PageSize, totals, &page.Until, version); err != nil {
			return page, err
		}
	}
	if err := s.files.read(s.files.path, days, uid, after, PageSize, totals, &page.Until, version); err != nil {
		return page, err
	}
	names := make([]string, 0, len(totals))
	for h := range totals {
		names = append(names, h)
	}
	sort.Strings(names)
	page.More = len(names) > PageSize
	page.Version = string(version.Sum(nil))
	page.Rows = make([]Row, 0, min(len(names), PageSize))
	for _, name := range names[:min(len(names), PageSize)] {
		page.Rows = append(page.Rows, totals[name])
	}
	return page, nil
}

// Query is the in-memory convenience API. Node reports stream individual pages.
func (s *Store) Query(uid int, day time.Time) ([]Row, int64, error) {
	var rows []Row
	var after *string
	var version string
	for {
		page, err := s.QueryPage(uid, day, after)
		if err != nil {
			return nil, 0, err
		}
		if after != nil && version != page.Version {
			return nil, 0, ErrSnapshotChanged
		}
		if len(rows)+len(page.Rows) > maxTrackedKeys {
			return nil, 0, ErrMemoryLimit
		}
		rows = append(rows, page.Rows...)
		if !page.More {
			return rows, page.Until, nil
		}
		version = page.Version
		after = &rows[len(rows)-1].Host
	}
}
