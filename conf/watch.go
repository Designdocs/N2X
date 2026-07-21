package conf

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Timings of the reload path. Variables rather than constants so tests can
// collapse them; they are read once, before the watcher goroutine starts.
var (
	watchDebounce = 10 * time.Second
	watchSettle   = 5 * time.Second
)

// Watch reloads the config whenever filePath or xDnsPath changes.
//
// The returned function stops watching and releases the underlying watcher.
// It is safe to call more than once. Watch returns a nil function when it
// fails, in which case nothing was started.
func (p *Conf) Watch(filePath, xDnsPath string, reload func()) (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("new watcher error: %s", err)
	}
	if err := watcher.Add(filePath); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch file error: %s", err)
	}
	if xDnsPath != "" {
		if err := watcher.Add(xDnsPath); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("watch dns file error: %s", err)
		}
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	debounce, settle := watchDebounce, watchSettle
	go func() {
		var pre time.Time
		defer watcher.Close()
		for {
			select {
			case <-done:
				return
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) {
					continue
				}
				if pre.Add(debounce).After(time.Now()) {
					continue
				}
				pre = time.Now()
				go p.reloadAfter(done, settle, e.Name, filePath, xDnsPath, reload)
			case err := <-watcher.Errors:
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	return stop, nil
}

// reloadAfter waits for the change to settle, then reloads the config and
// invokes reload. It gives up if the watcher is stopped while it waits.
func (p *Conf) reloadAfter(done <-chan struct{}, settle time.Duration, changed, filePath, xDnsPath string, reload func()) {
	select {
	case <-done:
		return
	case <-time.After(settle):
	}

	switch filepath.Base(strings.TrimSuffix(changed, "~")) {
	case filepath.Base(xDnsPath):
		log.Println("DNS file changed, reloading...")
	default:
		log.Println("config file changed, reloading...")
	}

	*p = *New()
	if err := p.LoadFromPath(filePath); err != nil {
		log.Printf("reload config error: %s", err)
	}
	reload()
	log.Println("reload config success")
}
