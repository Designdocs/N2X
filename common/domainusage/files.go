package domainusage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/flock"
	bolt "github.com/sagernet/bbolt"
	bolterrors "github.com/sagernet/bbolt/errors"
	"github.com/shirou/gopsutil/v4/disk"
)

const (
	MaxDiskBytes    int64 = 128 << 20
	MinFreeBytes    int64 = 1 << 30
	ResumeFreeBytes int64 = MinFreeBytes + 256<<20
)

var (
	ErrLowDisk     = errors.New("domain usage: insufficient free disk space")
	ErrDiskLimit   = errors.New("domain usage: disk budget exhausted")
	ErrMemoryLimit = errors.New("domain usage: in-memory domain limit reached")
	instanceName   = regexp.MustCompile("^[a-f0-9]{64}$")
)

type files struct {
	path           string // The pre-sharding database, also the stable node identity.
	limit, reserve int64
	free           func(string) (int64, error)
}

func FreeBytes(dir string) (int64, error) {
	u, err := disk.Usage(dir)
	if err != nil {
		return 0, err
	}
	return int64(u.Free), nil
}
func (f files) dayPath(day string) string {
	return strings.TrimSuffix(f.path, ".db") + "." + day + ".db"
}
func (f files) lock(write bool) (func() error, error) {
	l := flock.New(filepath.Join(filepath.Dir(f.path), ".quota.lock"))
	var err error
	if write {
		err = l.Lock()
	} else {
		err = l.RLock()
	}
	return l.Unlock, err
}

type storedFile struct {
	path, day string
	size      int64
	legacy    bool
}

func (f files) inventory() ([]storedFile, int64, error) {
	dir := filepath.Dir(f.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var list []storedFile
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, 0, err
		}
		total += info.Size()
		name := e.Name()
		if !strings.HasSuffix(name, ".db") {
			continue
		}
		stem := strings.TrimSuffix(name, ".db")
		id, day, dated := strings.Cut(stem, ".")
		if !instanceName.MatchString(id) && id != strings.TrimSuffix(filepath.Base(f.path), ".db") {
			continue
		}
		if dated {
			if _, err := time.Parse(time.DateOnly, day); err != nil {
				continue
			}
		} else {
			day = info.ModTime().UTC().Format(time.DateOnly)
		}
		list = append(list, storedFile{filepath.Join(dir, name), day, info.Size(), !dated})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].day < list[j].day || list[i].day == list[j].day && list[i].path < list[j].path
	})
	return list, total, nil
}

// A legacy database may still be owned by an older process. Only retire a
// recognised statistics database after acquiring its lock and checking its schema.
func removeStatistics(file storedFile) error {
	if file.legacy {
		db, err := bolt.Open(file.path, 0600, &bolt.Options{ReadOnly: true, Timeout: 50 * time.Millisecond})
		if err != nil {
			return err
		}
		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("meta"))
			if b == nil || len(b.Get([]byte("until"))) != 8 {
				return fmt.Errorf("unrecognised legacy statistics database %s", file.path)
			}
			return nil
		})
		if e := db.Close(); e != nil {
			return e
		}
		if err != nil {
			return err
		}
	}
	return os.Remove(file.path)
}

// prune runs under the directory write lock shared by all local controllers/processes.
func (f files) prune(today time.Time) ([]storedFile, int64, error) {
	list, total, err := f.inventory()
	if err != nil {
		return nil, 0, err
	}
	cutoff := today.UTC().AddDate(0, 0, -29).Format(time.DateOnly)
	keep := list[:0]
	for _, file := range list {
		if file.day < cutoff || file.legacy && file.size > f.limit {
			if err := removeStatistics(file); err != nil {
				return nil, 0, err
			}
			total -= file.size
		} else {
			keep = append(keep, file)
		}
	}
	return keep, total, nil
}

func (f files) writeDay(day string, through time.Time, rows map[Key]Row) error {
	list, total, err := f.prune(through)
	if err != nil {
		return err
	}
	path := f.dayPath(day)
	var existing int64
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected domain usage file %s", path)
		}
		existing = info.Size()
	} else if !os.IsNotExist(e) {
		return e
	}
	for {
		free, err := f.free(filepath.Dir(path))
		if err != nil {
			return err
		}
		if free <= f.reserve {
			return ErrLowDisk
		}
		limit := min(f.limit-total+existing, existing+free-f.reserve)
		if limit >= int64(os.Getpagesize()*4) && limit >= existing {
			err = f.update(path, day, through, rows, int(limit))
			if err == nil {
				return nil
			}
			if !errors.Is(err, bolterrors.ErrMaxSizeReached) {
				return err
			}
			// An unsuccessful first transaction can still have created the initial file.
			if info, e := os.Stat(path); e == nil {
				total += info.Size() - existing
				existing = info.Size()
			}
		}
		removed := false
		for len(list) > 0 {
			old := list[0]
			list = list[1:]
			if old.path == path || old.day >= day {
				continue
			}
			if err := removeStatistics(old); err != nil {
				return err
			}
			total -= old.size
			removed = true
			break
		}
		if !removed {
			if free-f.reserve < f.limit-total {
				return ErrLowDisk
			}
			return ErrDiskLimit
		}
	}
}
func (f files) update(path, day string, through time.Time, rows map[Key]Row, limit int) error {
	db, err := bolt.Open(path, 0600, &bolt.Options{MaxSize: limit, Timeout: time.Second})
	if err != nil {
		return err
	}
	db.AllocSize = os.Getpagesize()
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(day))
		if err != nil {
			return err
		}
		for k, delta := range rows {
			key := binary.BigEndian.AppendUint64(nil, uint64(k.UID))
			key = append(key, k.Host...)
			r := decode(b.Get(key))
			r.add(delta)
			if err := b.Put(key, encode(r)); err != nil {
				return err
			}
		}
		meta, err := tx.CreateBucketIfNotExists([]byte("meta"))
		if err != nil {
			return err
		}
		return meta.Put([]byte("until"), binary.BigEndian.AppendUint64(nil, uint64(through.Unix())))
	})
	return errors.Join(err, db.Close())
}

// Each bucket is ordered by (user, hostname). A hostname in the first N
// global results is necessarily in the first N results of every bucket in
// which it occurs. Read one extra to distinguish a final full page.
func (f files) read(path string, days []string, uid int, after *string, limit int, totals map[string]Row, until *int64, version hash.Hash) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unexpected domain usage file %s", path)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	err = db.View(func(tx *bolt.Tx) error {
		fmt.Fprintf(version, "%s:%d:%d;", filepath.Base(path), info.ModTime().UnixNano(), tx.ID())
		prefix := binary.BigEndian.AppendUint64(nil, uint64(uid))
		start := prefix
		if after != nil {
			start = append(bytes.Clone(prefix), (*after)...)
		}
		for _, day := range days {
			b := tx.Bucket([]byte(day))
			if b == nil {
				continue
			}
			if meta := tx.Bucket([]byte("meta")); meta != nil {
				if v := meta.Get([]byte("until")); len(v) == 8 {
					*until = max(*until, int64(binary.BigEndian.Uint64(v)))
				}
			}
			c := b.Cursor()
			k, v := c.Seek(start)
			if after != nil && bytes.Equal(k, start) {
				k, v = c.Next()
			}
			for n := 0; n <= limit && k != nil && bytes.HasPrefix(k, prefix); n++ {
				host := string(k[8:])
				r := totals[host]
				r.Host = host
				r.add(decode(v))
				totals[host] = r
				k, v = c.Next()
			}
		}
		return nil
	})
	return errors.Join(err, db.Close())
}

// Old single-file stores stay readable during the 30-day transition. Expire
// their day buckets with a bounded write, preserving unexpired rows when possible.
func (f files) expireLegacy(file storedFile, cutoff string, total int64) error {
	db, err := bolt.Open(file.path, 0600, &bolt.Options{ReadOnly: true, Timeout: 50 * time.Millisecond})
	if err != nil {
		return err
	}
	var expired [][]byte
	var live bool
	err = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta == nil || len(meta.Get([]byte("until"))) != 8 {
			return fmt.Errorf("unrecognised legacy statistics database %s", file.path)
		}
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if _, err := time.Parse(time.DateOnly, string(name)); err != nil {
				return nil
			}
			if string(name) < cutoff {
				expired = append(expired, bytes.Clone(name))
			} else {
				live = true
			}
			return nil
		})
	})
	if err = errors.Join(err, db.Close()); err != nil {
		return err
	}
	if !live {
		return removeStatistics(file)
	}
	if len(expired) == 0 {
		return nil
	}
	free, err := f.free(filepath.Dir(file.path))
	if err != nil {
		return err
	}
	if free <= f.reserve {
		return removeStatistics(file)
	}
	limit := min(f.limit-total+file.size, file.size+free-f.reserve)
	db, err = bolt.Open(file.path, 0600, &bolt.Options{MaxSize: int(limit), Timeout: 50 * time.Millisecond})
	if err != nil {
		return err
	}
	db.AllocSize = os.Getpagesize()
	err = db.Update(func(tx *bolt.Tx) error {
		for _, d := range expired {
			if err := tx.DeleteBucket(d); err != nil {
				return err
			}
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil {
		return closeErr
	}
	if errors.Is(err, bolterrors.ErrMaxSizeReached) {
		return removeStatistics(file)
	}
	return err
}

// Maintain removes expired daily files even while collection is switched off.
func Maintain(path string, now time.Time) error {
	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	f := files{path, MaxDiskBytes, MinFreeBytes, FreeBytes}
	unlock, err := f.lock(true)
	if err != nil {
		return err
	}
	defer unlock()
	keep, total, err := f.prune(now)
	if err != nil {
		return err
	}
	for _, old := range keep {
		if total > f.limit {
			if err := removeStatistics(old); err != nil {
				return err
			}
			total -= old.size
			continue
		}
		if old.legacy {
			if err := f.expireLegacy(old, now.UTC().AddDate(0, 0, -29).Format(time.DateOnly), total); err != nil {
				return err
			}
			total -= old.size
			if info, e := os.Stat(old.path); e == nil {
				total += info.Size()
			} else if !os.IsNotExist(e) {
				return e
			}
		}
	}
	if total > f.limit {
		return ErrDiskLimit
	}
	return nil
}
