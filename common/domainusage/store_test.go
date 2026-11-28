package domainusage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRollingRetentionAndHistoricalRate(t *testing.T) {
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	name := filepath.Join(t.TempDir(), "usage.db")
	s, err := Open(name, 2)
	if err != nil {
		t.Fatal(err)
	}
	expired, release := s.Track(1, "expired.example")
	expired.Bytes.Add(90)
	release()
	if err := s.Flush(at.AddDate(0, 0, -30)); err != nil {
		t.Fatal(err)
	}
	older, release := s.Track(1, "CDN.Example.")
	older.Bytes.Add(100)
	release()
	if err := s.Flush(at.AddDate(0, 0, -29)); err != nil {
		t.Fatal(err)
	}
	f, end := s.Track(1, "cdn.example")
	f.Bytes.Add(4)
	half := 0.5
	s.StartBilling(at)(&half)
	f.Bytes.Add(10)
	zero := 0.
	s.StartBilling(at)(&zero)
	end()
	for _, bad := range []string{"192.0.2.1", "2001:db8::1", "https://example.org/private"} {
		_, end = s.Track(2, bad)
		end()
	}
	if err = s.Close(at); err != nil {
		t.Fatal(err)
	}
	s, err = Open(name, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(at)
	rows, until, err := s.Query(1, at)
	if err != nil || until != at.Unix() || len(rows) != 1 || rows[0] != (Row{"cdn.example", 114, 202, 2}) {
		t.Fatalf("rows=%+v until=%d err=%v", rows, until, err)
	}
	rows, _, _ = s.Query(2, at)
	if len(rows) != 1 || rows[0].Host != "" || rows[0].Connections != 3 {
		t.Fatalf("unexpected unknown rows %+v", rows)
	}
}
