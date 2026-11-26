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
	return requestFilter(tag, cfg, probeKey)
}

func SensitiveFilter(tag string, cfg conf.WSScanGuardConfig) func(*http.Request) bool {
	return requestFilter(tag, cfg, sensitiveKey)
}

func requestFilter(tag string, cfg conf.WSScanGuardConfig, classify func(*http.Request) string) func(*http.Request) bool {
	if !cfg.Enabled {
		return nil
	}
	root := auditDir()
	return func(r *http.Request) bool {
		reason := classify(r)
		if reason == "" {
			return false
		}
		label := r.URL.Path
		if len(label) > 256 {
			label = label[:256] + "…"
		}
		var source, action string
		if HasRelayCA(cfg) || len(cfg.DirectOnlyNodes) > 0 {
			if v, ok := visitorFor(tag, r); ok {
				source = v.ip.String()
				banned, err := v.observe(r.URL.Path, time.Now())
				if err != nil {
					log.Printf("node scan guard: save ban: %v", err)
				}
				if banned {
					action = "node-ban"
					if v.feedback != nil {
						if err := v.feedback.ban(v.ip); err != nil {
							log.Printf("node %s: notify relay of ban: %v", tag, err)
						}
					}
				}
			}
		}
		data, err := json.Marshal(struct {
			Visitor string    `json:"visitor,omitempty"`
			Action  string    `json:"action,omitempty"`
			Time    time.Time `json:"time"`
			Node    string    `json:"node"`
			Path    string    `json:"path"`
			Rule    string    `json:"rule"`
		}{source, action, time.Now().UTC(), tag, label, reason})
		if err == nil {
			err = appendWSAudit(root, append(data, '\n'), int64(cfg.LogMaxMB)<<20)
		}
		if err != nil {
			log.Printf("node scan guard: write log: %v", err)
		}
		return true
	}
}
func sensitiveKey(r *http.Request) string {
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
	return ""
}

func probeKey(r *http.Request) string {
	if reason := sensitiveKey(r); reason != "" {
		return reason
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
