package conf

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
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

// Watch reloads the config whenever filePath or xDnsPath changes. A DNS file
// that does not exist yet is watched through its directory. The new file is
// validated with opts first; if it has any problem, or a warning the running
// config does not have, the running config is kept, reload is not called and
// the error goes to rejected, or to the log when rejected is nil.
//
// The returned function stops watching, releases the underlying watcher and
// waits for a reload already in progress to finish, so the caller can tear
// down what reload manages afterwards. It is safe to call more than once but
// must not be called from reload. Watch returns a nil function when it fails,
// in which case nothing was started.
func (p *Conf) Watch(filePath, xDnsPath string, opts ValidateOptions, reload func(), rejected func(error)) (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("new watcher error: %w", err)
	}
	if err := watcher.Add(filePath); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch file error: %w", err)
	}
	// dnsDir is set when the DNS file does not exist yet: its directory is
	// watched instead, so the file is picked up once xray writes it.
	var dnsDir string
	if xDnsPath != "" {
		target := xDnsPath
		if _, err := os.Stat(xDnsPath); errors.Is(err, fs.ErrNotExist) {
			dnsDir = filepath.Dir(xDnsPath)
			target = dnsDir
		}
		if err := watcher.Add(target); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("watch dns file error: %w", err)
		}
	}

	done, exited := make(chan struct{}), make(chan struct{})
	// reloads is only added to by the watcher goroutine, so once exited is
	// closed no new reload can start and Wait is safe.
	var (
		once    sync.Once
		reloads sync.WaitGroup
	)
	stop := func() {
		once.Do(func() { close(done) })
		<-exited
		reloads.Wait()
	}

	debounce, settle := watchDebounce, watchSettle
	go func() {
		defer close(exited)
		defer watcher.Close()
		var timer *time.Timer
		var timerC <-chan time.Time
		var previous, lastEvent time.Time
		var changed string
		var pending, active bool
		finished := make(chan struct{}, 1)
		defer func() {
			if timer != nil {
				timer.Stop()
			}
		}()
		schedule := func() {
			deadline := lastEvent.Add(settle)
			if earliest := previous.Add(debounce); earliest.After(deadline) {
				deadline = earliest
			}
			delay := time.Until(deadline)
			if delay < 0 {
				delay = 0
			}
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
			}
			timerC = timer.C
		}
		for {
			select {
			case <-done:
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// kqueue can merge a write and an attribute change into one
				// event; only a bare chmod leaves the content untouched.
				if event.Op == fsnotify.Chmod {
					continue
				}
				if dnsDir != "" && isOtherFileIn(dnsDir, event.Name, filePath, xDnsPath) {
					continue
				}
				changed, lastEvent, pending = event.Name, time.Now(), true
				schedule()
			case <-timerC:
				timerC = nil
				if !pending || active {
					continue
				}
				pending, active, previous = false, true, time.Now()
				currentChange := changed
				reloads.Add(1)
				go func() {
					defer reloads.Done()
					p.reloadChanged(done, currentChange, filePath, xDnsPath, opts, reload, rejected)
					select {
					case finished <- struct{}{}:
					case <-done:
					}
				}()
			case <-finished:
				active = false
				if pending {
					schedule()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	return stop, nil
}

// reloadChanged validates the latest settled files. The watcher starts only
// one reload at a time and retains edits arriving during a reload or cooldown.
func (p *Conf) reloadChanged(done <-chan struct{}, changed, filePath, xDnsPath string, opts ValidateOptions, reload func(), rejected func(error)) {
	switch filepath.Base(strings.TrimSuffix(changed, "~")) {
	case filepath.Base(xDnsPath):
		log.Println("DNS file changed, reloading...")
	default:
		log.Println("config file changed, reloading...")
	}

	select {
	case <-done:
		return
	default:
	}
	next, err := LoadValidated(filePath, opts)
	if err == nil {
		// A warning is part of the config left out; the running config
		// still has that part, so the reload must not drop it.
		if added := newWarnings(p.Warnings, next.Warnings); len(added) > 0 {
			err = &ValidationError{File: filePath, Issues: added}
		}
	}
	if err != nil {
		if rejected != nil {
			rejected(err)
		} else {
			log.Printf("reload rejected, keeping the running config: %s", err)
		}
		return
	}
	*p = *next
	reload()
	log.Println("reload config success")
}

// isOtherFileIn reports whether name, an event from the watched directory
// dir, is about a file other than the watched ones.
func isOtherFileIn(dir, name string, watched ...string) bool {
	name = filepath.Clean(strings.TrimSuffix(name, "~"))
	if filepath.Dir(name) != filepath.Clean(dir) {
		return false
	}
	for _, path := range watched {
		if name == filepath.Clean(path) {
			return false
		}
	}
	return true
}
