package domainusage

import (
	"errors"
	"fmt"
	bolt "github.com/sagernet/bbolt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectoryQuotaRetiresOldestFirst(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	a, _ := Open(filepath.Join(dir, strings.Repeat("a", 64)+".db"), 1)
	b, _ := Open(filepath.Join(dir, strings.Repeat("b", 64)+".db"), 1)
	defer a.Pause()
	defer b.Pause()
	for _, s := range []*Store{a, b} {
		s.files.limit = int64(os.Getpagesize()) * 36
	}
	unrelated := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(unrelated, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		owner := []*Store{a, b}[i%2]
		day := now.AddDate(0, 0, i-9)
		for j := 0; j < 300; j++ {
			f, release := owner.Track(1, fmt.Sprintf("name-%03d.domain.example", j))
			f.Bytes.Add(15)
			release()
		}
		if err := owner.Flush(day); err != nil {
			t.Fatalf("day %d: %v", i, err)
		}
		_, size, err := a.files.inventory()
		if err != nil || size > a.files.limit {
			t.Fatal(size, err)
		}
		rows, _, err := owner.Query(1, day)
		if err != nil || len(rows) != 300 {
			t.Fatalf("latest rows=%d, error=%v", len(rows), err)
		}
	}
	if _, err := os.Stat(a.files.dayPath(now.AddDate(0, 0, -9).Format(time.DateOnly))); !os.IsNotExist(err) {
		t.Fatal("oldest file survived pressure", err)
	}
	if raw, err := os.ReadFile(unrelated); err != nil || string(raw) != "safe" {
		t.Fatal("unrelated file changed")
	}
}
func TestCurrentDayCannotOutgrowCapAndLowDiskWritesNothing(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "meter.db"), 1)
	defer s.Pause()
	now := time.Now()
	s.files.limit = 64 << 10
	for i := 0; i < 4000; i++ {
		_, done := s.Track(i+1, "example.org")
		done()
	}
	if err := s.Flush(now); !errors.Is(err, ErrDiskLimit) {
		t.Fatalf("full: %v", err)
	}
	_, used, _ := s.files.inventory()
	if used > s.files.limit {
		t.Fatalf("over budget %d", used)
	}
	s.files.free = func(string) (int64, error) { return s.files.reserve - 1, nil }
	if err := s.Flush(now); !errors.Is(err, ErrLowDisk) {
		t.Fatalf("low disk: %v", err)
	}
	_, after, _ := s.files.inventory()
	if after != used {
		t.Fatalf("grew %d -> %d", used, after)
	}
}
func TestBoundAcrossBillingIntervals(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "usage.db"), 1)
	for i := 0; i < maxTrackedKeys; i++ {
		f, done := s.Track(i+1, "example.test")
		if f == nil {
			t.Fatal(i)
		}
		done()
		if i%2048 == 0 {
			s.StartBilling(time.Now())(nil)
		}
	}
	f, _ := s.Track(maxTrackedKeys+1, "new.example")
	if f != nil || !s.MemoryFull() {
		t.Fatal("unexpected allocation")
	}
	s.Pause()
	if trackedKeys.Load() != 0 {
		t.Fatal("leaked slots", trackedKeys.Load())
	}
}

func TestLegacyAndDailyPagesRemainExactAcrossQuotaCleanup(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	s, err := Open(filepath.Join(dir, strings.Repeat("d", 64)+".db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Pause()
	old := now.AddDate(0, 0, -30).Format(time.DateOnly)
	recent := now.AddDate(0, 0, -2).Format(time.DateOnly)
	if err := s.files.update(s.files.path, old, now, map[Key]Row{{7, "expired.example"}: {Raw: 70}}, int(s.files.limit)); err != nil {
		t.Fatal(err)
	}
	if err := s.files.update(s.files.path, recent, now, map[Key]Row{{7, "host-000.example"}: {Raw: 5}}, int(s.files.limit)); err != nil {
		t.Fatal(err)
	}
	if err := Maintain(s.files.path, now); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(s.files.path, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	err = db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(old)) != nil || tx.Bucket([]byte(recent)) == nil {
			return errors.New("legacy retention")
		}
		return nil
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for day := 0; day < 2; day++ {
		for i := 0; i < 710; i++ {
			f, release := s.Track(7, fmt.Sprintf("host-%03d.example", i))
			f.Bytes.Add(int64(1 + day))
			release()
		}
		if err := s.Flush(now.AddDate(0, 0, day-1)); err != nil {
			t.Fatal(err)
		}
	}
	var after *string
	var names []string
	var version string
	for i := 0; i < 3; i++ {
		p, err := s.QueryPage(7, now, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Rows) != []int{300, 300, 110}[i] || p.More != (i < 2) || i > 0 && version != p.Version {
			t.Fatal("inconsistent page", i)
		}
		for _, r := range p.Rows {
			want := int64(3)
			if len(names) == 0 {
				want += 5
			}
			if r.Raw != want || r.Host != fmt.Sprintf("host-%03d.example", len(names)) {
				t.Fatal("missing or duplicated", r)
			}
			names = append(names, r.Host)
		}
		version = p.Version
		after = &p.Rows[len(p.Rows)-1].Host
	}
	if err := s.Flush(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	next, err := s.QueryPage(7, now, nil)
	if err != nil || next.Version == version {
		t.Fatal("did not detect new hourly snapshot")
	}
}

func TestConcurrentInstancesSharePhysicalFileLimit(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	const count = 4
	errs := make(chan error, count)
	limit := int64(os.Getpagesize()) * 28
	for i := 0; i < count; i++ {
		go func(id int) {
			s, err := Open(filepath.Join(dir, fmt.Sprintf("%064x.db", id)), 1)
			if err != nil {
				errs <- err
				return
			}
			s.files.limit = limit
			for j := 0; j < 300; j++ {
				f, release := s.Track(j+1, "concurrent.example")
				f.Bytes.Add(10)
				release()
			}
			err = s.Flush(now)
			s.Pause()
			errs <- err
		}(i)
	}
	for i := 0; i < count; i++ {
		if err := <-errs; err != nil && !errors.Is(err, ErrDiskLimit) {
			t.Fatal(err)
		}
	}
	f := files{path: filepath.Join(dir, "node.db")}
	_, total, err := f.inventory()
	if err != nil || total > limit || total == 0 {
		t.Fatal("directory budget", total, limit, err)
	}
}
