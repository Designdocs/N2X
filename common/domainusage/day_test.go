package domainusage

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestDaySnapshotSeparatesUTCAndPreservesPendingCounters(t *testing.T) {
	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1).Truncate(24 * time.Hour)
	store, err := Open(filepath.Join(t.TempDir(), "usage.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Pause()
	add := func(id int, host string, n int64) { f, end := store.Track(id, host); f.Bytes.Add(n); end() }
	add(7, "old.test", 11)
	if err = store.Flush(yesterday.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	add(7, "old.test", 5)
	store.StartBilling(yesterday.Add(23 * time.Hour))(nil)
	add(7, "today.test", 9)
	add(8, "another.test", 17)
	check := func(day time.Time, uid int, host string, bytes int64, available bool) {
		p, err := store.DayPages(uid, day, now)(nil)
		if err != nil || (p.Until > 0) != available {
			t.Fatalf("day %s: %+v %v", day, p, err)
		}
		if host == "" {
			if len(p.Rows) != 0 {
				t.Fatal(p.Rows)
			}
			return
		}
		if len(p.Rows) != 1 || p.Rows[0].Host != host || p.Rows[0].Raw != bytes || p.Rows[0].Weighted != 2*float64(bytes) {
			t.Fatal(p.Rows)
		}
	}
	check(yesterday, 7, "old.test", 16, true)
	check(now, 7, "today.test", 9, true)
	check(yesterday, 8, "", 0, true)
	check(yesterday.AddDate(0, 0, -1), 7, "", 0, false)
	if err = store.Flush(now); err != nil {
		t.Fatal(err)
	}
	check(now, 7, "today.test", 9, true)
	check(yesterday, 7, "old.test", 16, true)
	if !ValidDay(now.Truncate(24*time.Hour).AddDate(0, 0, -29), now) || ValidDay(yesterday.AddDate(0, 0, -29), now) || ValidDay(now.AddDate(0, 0, 1), now) {
		t.Fatal("retention bounds")
	}
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		serveLocal(server, store.files.path, "example.org", "panel", 1, func() *Store { return store })
	}()
	defer client.Close()
	groups := map[string]*LocalResult{}
	if err = collectLocal(client, localQuery{7, yesterday.Format(time.DateOnly)}, groups); err != nil {
		t.Fatal(err)
	}
	if groups["panel"].Rows["old.test"].Raw != 16 {
		t.Fatal(groups)
	}
}
