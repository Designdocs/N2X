package domainusage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/flock"
)

const DefaultDir = "/var/lib/N2X/domain-usage"

func Directory() string {
	if d := os.Getenv("N2X_DOMAIN_USAGE_DIR"); d != "" {
		return d
	}
	return DefaultDir
}

type localQuery struct {
	Status bool `json:",omitempty"`
	UID    int
	Day    string
}
type localReply struct {
	State        string `json:",omitempty"`
	Panel, Group string
	Node         int
	Rows         []Row
	Until        int64
	Done         bool
	Error        string
}

// The local CLI reaches the same counters as a panel query, including this hour.
// Restrict access to the owner of the filesystem socket.
func ListenLocal(path, panel string, node int, current func() *Store) (net.Listener, error) {
	return ListenLocalWithStatus(path, panel, node, current, nil)
}

func ListenLocalWithStatus(path, panel string, node int, current func() *Store, status func() string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "query-"+fmt.Sprintf("%x", sha256.Sum256([]byte(filepath.Base(path))))[:20]+".sock")
	lock := flock.New(filepath.Join(dir, ".quota.lock"))
	if err := lock.Lock(); err != nil {
		return nil, err
	}
	defer lock.Unlock()
	if info, err := os.Lstat(name); err == nil && info.Mode()&os.ModeSocket != 0 {
		probe, err := net.DialTimeout("unix", name, time.Second)
		if err == nil {
			probe.Close()
			return nil, fmt.Errorf("local query socket already in use")
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			if err = os.Remove(name); err != nil {
				return nil, err
			}
		}
	}
	l, err := net.Listen("unix", name)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(name, 0600); err != nil {
		l.Close()
		return nil, err
	}
	label := ""
	if u, e := url.Parse(panel); e == nil {
		label = u.Host
	}
	group := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimRight(panel, "/"))))
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(time.Minute))
			serveLocal(conn, path, label, group, node, current, status)
			conn.Close()
		}
	}()
	return l, nil
}

func serveLocal(c net.Conn, path, panel, group string, node int, current func() *Store, status func() string) {
	enc := json.NewEncoder(c)
	fail := func(e error) { _ = enc.Encode(localReply{Error: e.Error()}) }
	var q localQuery
	if err := json.NewDecoder(io.LimitReader(c, 1024)).Decode(&q); err != nil {
		fail(err)
		return
	}
	if q.Status {
		var state string
		if status != nil {
			state = status()
		}
		_ = enc.Encode(localReply{Panel: panel, Node: node, State: state})
		return
	}
	now := time.Now().UTC()
	date, err := time.Parse(time.DateOnly, q.Day)
	if q.UID < 1 || q.Day != "" && (err != nil || !ValidDay(date, now)) {
		fail(errors.New("用户 ID 或 UTC 日期无效"))
		return
	}
	s := current()
	var read func(*string) (Page, error)
	if s == nil {
		// Pausing collection preserves already-flushed data for local inspection.
		s, err = Open(path, 0)
		if err != nil {
			fail(err)
			return
		}
		defer s.Pause()
		end, days := now, 30
		if q.Day != "" {
			end, days = date, 1
		}
		read = func(after *string) (Page, error) { return s.queryPage(q.UID, end, days, after, nil) }
	} else if q.Day != "" {
		read = s.DayPages(q.UID, date, now)
	} else {
		read = s.LivePages(q.UID, now)
	}
	var after *string
	var version string
	for {
		if err := s.Context().Err(); err != nil {
			fail(err)
			return
		}
		p, err := read(after)
		if err != nil {
			fail(err)
			return
		}
		if after != nil && version != p.Version {
			fail(ErrSnapshotChanged)
			return
		}
		if enc.Encode(localReply{Panel: panel, Group: group, Node: node, Rows: p.Rows, Until: p.Until, Done: !p.More}) != nil || !p.More {
			return
		}
		version = p.Version
		after = &p.Rows[len(p.Rows)-1].Host
	}
}

type LocalResult struct {
	Panel          string
	Nodes, Missing []int
	Rows           map[string]Row
}

func LocalResults(dir string, uid int, day string) ([]LocalResult, error) {
	if uid < 1 {
		return nil, errors.New("用户 ID 须为正整数")
	}
	if day != "" {
		date, err := time.Parse(time.DateOnly, day)
		if err != nil || !ValidDay(date, time.Now()) {
			return nil, errors.New("请选择近 30 天内的 UTC 日期")
		}
	}
	groups := map[string]*LocalResult{}
	err := visitLocal(dir, 2*time.Second, func(c net.Conn) error {
		return collectLocal(c, localQuery{UID: uid, Day: day}, groups)
	})
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, errors.New("未找到运行中的域名查询服务")
	}
	var results []LocalResult
	for _, r := range groups {
		sort.Ints(r.Nodes)
		sort.Ints(r.Missing)
		results = append(results, *r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Panel < results[j].Panel })
	return results, nil
}

func visitLocal(dir string, timeout time.Duration, visit func(net.Conn) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "query-") || entry.Type()&os.ModeSocket == 0 {
			continue
		}
		c, err := net.DialTimeout("unix", filepath.Join(dir, entry.Name()), timeout)
		if errors.Is(err, syscall.ECONNREFUSED) || os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		err = visit(c)
		c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func collectLocal(c net.Conn, q localQuery, groups map[string]*LocalResult) error {
	c.SetDeadline(time.Now().Add(time.Minute))
	if err := json.NewEncoder(c).Encode(q); err != nil {
		return err
	}
	dec := json.NewDecoder(c)
	for {
		var p localReply
		if err := dec.Decode(&p); err != nil {
			return err
		}
		if p.Error != "" {
			return errors.New(p.Error)
		}
		g := groups[p.Group]
		if g == nil {
			g = &LocalResult{Panel: p.Panel, Rows: map[string]Row{}}
			groups[p.Group] = g
		}
		for _, v := range p.Rows {
			r := g.Rows[v.Host]
			r.Host = v.Host
			r.add(v)
			g.Rows[v.Host] = r
		}
		if len(g.Rows) > maxTrackedKeys {
			return ErrMemoryLimit
		}
		if p.Done {
			g.Nodes = append(g.Nodes, p.Node)
			if p.Until == 0 {
				g.Missing = append(g.Missing, p.Node)
			}
			return nil
		}
	}
}
