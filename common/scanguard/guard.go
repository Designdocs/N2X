package scanguard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Designdocs/N2X/conf"
	ws "github.com/gorilla/websocket"
)

// Filter is invoked only after the listener rejects a transport path or
// identifies a request as addressed to the node's own website.
func Filter(tag string, cfg conf.WSScanGuardConfig) func(*http.Request) bool {
	if !cfg.Enabled {
		return nil
	}
	root := os.Getenv("N2X_WS_SCAN_STATE_DIR")
	if root == "" {
		root = "/var/lib/N2X/ws-scan"
	}
	return func(r *http.Request) bool {
		reason := probeKey(r)
		if reason == "" {
			return false
		}
		label := r.URL.Path
		if len(label) > 256 {
			label = label[:256] + "…"
		}
		data, err := json.Marshal(struct {
			Time time.Time `json:"time"`
			Node string    `json:"node"`
			Path string    `json:"path"`
			Rule string    `json:"rule"`
		}{time.Now().UTC(), tag, label, reason})
		if err == nil {
			err = appendWSAudit(root, append(data, '\n'), int64(cfg.LogMaxMB)<<20)
		}
		if err != nil {
			log.Printf("node scan guard: write log: %v", err)
		}
		return true
	}
}
func probeKey(r *http.Request) string {
	p := strings.ToLower(path.Clean(r.URL.Path))
	switch {
	case p == "/.git" || strings.HasPrefix(p, "/.git/"):
		return "git"
	case p == "/.env" || strings.HasPrefix(p, "/.env."):
		return "environment"
	case p == "/wp-login.php" || p == "/wp-admin" || strings.HasPrefix(p, "/wp-admin/"):
		return "wordpress"
	case p == "/phpmyadmin" || strings.HasPrefix(p, "/phpmyadmin/"):
		return "phpmyadmin"
	case p == "/actuator/env" || p == "/actuator/heapdump":
		return "actuator"
	}
	if r.Method == "GET" && ws.IsWebSocketUpgrade(r) && r.Header.Get("Sec-WebSocket-Version") == "13" {
		key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
		if err == nil && len(key) == 16 {
			return "websocket"
		}
	}
	return ""
}

// All node listeners in this process share the same two audit segments.
var wsAuditMu sync.Mutex

func appendWSAudit(root string, data []byte, limit int64) error {
	wsAuditMu.Lock()
	defer wsAuditMu.Unlock()
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	path := filepath.Join(root, "intercepts.jsonl")
	half := limit / 2
	for _, file := range []string{path + ".1", path} {
		info, err := os.Stat(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Size() > half {
			if err := os.Remove(file); err != nil {
				return err
			}
			continue
		}
		if file == path && info.Size()+int64(len(data)) > half {
			if err := os.Rename(path, path+".1"); err != nil {
				return err
			}
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}
