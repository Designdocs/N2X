package scanguard

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const roundGap = 10 * time.Minute

func auditDir() string {
	if dir := os.Getenv("N2X_WS_SCAN_STATE_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/N2X/ws-scan"
}
func (v verifiedVisitor) banFile() string {
	return filepath.Join(auditDir(), "bans", fmt.Sprintf("%x", sha256.Sum256([]byte(v.tag))), v.ip.String())
}
func (v verifiedVisitor) blocked() bool {
	info, err := os.Stat(v.banFile())
	return err == nil && info.Mode().IsRegular()
}

type scanRound struct {
	last, start, qualified time.Time
	paths                  map[string]bool
	prior                  bool
}

var evidence = struct {
	sync.Mutex
	rounds    map[verifiedVisitor]*scanRound
	nextSweep time.Time
}{rounds: make(map[verifiedVisitor]*scanRound)}

func (v verifiedVisitor) observe(p string, now time.Time) (bool, error) {
	evidence.Lock()
	defer evidence.Unlock()
	if !now.Before(evidence.nextSweep) {
		for k, r := range evidence.rounds {
			if now.Sub(r.last) > 24*time.Hour {
				delete(evidence.rounds, k)
			}
		}
		evidence.nextSweep = now.Add(time.Minute)
	}
	r := evidence.rounds[v]
	if r == nil || now.Sub(r.last) >= roundGap || now.Sub(r.start) > 5*time.Minute {
		var qualified time.Time
		prior := false
		if r != nil {
			qualified = r.qualified
			prior = now.Sub(qualified) <= 24*time.Hour && (r.prior || now.Sub(r.last) >= roundGap)
		}
		if r == nil && len(evidence.rounds) >= 16384 {
			return false, nil
		}
		r = &scanRound{start: now, paths: make(map[string]bool), prior: prior, qualified: qualified}
		evidence.rounds[v] = r
	}
	r.last = now
	if len(p) > 512 {
		return false, nil
	}
	if len(r.paths) < 3 {
		r.paths[path.Clean(strings.ToLower(p))] = true
	}
	if len(r.paths) >= 3 {
		r.qualified = now
	}
	if !r.prior || len(r.paths) < 3 {
		return false, nil
	}
	file := v.banFile()
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return false, err
	}
	evidenceFile, err := os.CreateTemp(filepath.Dir(file), ".ban-")
	if err != nil {
		return false, err
	}
	defer os.Remove(evidenceFile.Name())
	record := struct {
		Time    time.Time `json:"time"`
		Node    string    `json:"node"`
		Visitor string    `json:"visitor"`
	}{now.UTC(), v.tag, v.ip.String()}
	err = json.NewEncoder(evidenceFile).Encode(record)
	closeErr := evidenceFile.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	if err := os.Rename(evidenceFile.Name(), file); err != nil {
		return false, err
	}
	delete(evidence.rounds, v)
	return true, nil
}
func visitorFor(tag string, r *http.Request) (attributedConnection, bool) {
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if addr == nil {
		return attributedConnection{}, false
	}
	value, ok := verifiedVisitors.Load(addr)
	if !ok {
		return attributedConnection{}, false
	}
	v := value.(attributedConnection)
	return v, v.tag == tag
}
