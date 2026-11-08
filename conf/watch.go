package conf

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
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

// Watch reloads when a write to a watched config file changes
// the effective configuration. The new configuration is
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
	return p.WatchWithError(filePath, xDnsPath, opts, func() error {
		reload()
		return nil
	}, rejected)
}

// WatchWithError also preserves a failed reload for retry on the next write,
// including an identical write. The callback must report incomplete rebuilds.
func (p *Conf) WatchWithError(filePath, xDnsPath string, opts ValidateOptions, reload func() error, rejected func(error)) (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("new watcher error: %w", err)
	}
	if _, err := os.Stat(filePath); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch file error: %w", err)
	}
	var state watchState
	initial := p
	if p.loadedWatchState != nil {
		// Use the config actually loaded before startup. Reading the current
		// file here would silently adopt an edit that has not been applied.
		state = *p.loadedWatchState
		state.addFile(xDnsPath)
	} else {
		// Compatibility for callers that constructed Conf themselves.
		initial, err = LoadValidated(filePath, opts)
		if err != nil {
			watcher.Close()
			return nil, fmt.Errorf("snapshot watched config: %w", err)
		}
		state, err = snapshotWatchState(initial, xDnsPath)
		if err != nil {
			watcher.Close()
			return nil, fmt.Errorf("snapshot watched config: %w", err)
		}
	}
	targets := watchTargets{watcher: watcher, outbounds: opts.ReloadOutbounds != nil}
	if _, err := targets.update(filePath, xDnsPath, initial); err != nil {
		watcher.Close()
		return nil, err
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
		for _, kind := range targets.files {
			if kind == "outbound" {
				// An edit can arrive between loading the initial config and
				// attaching the watches after the nodes start.
				changed, lastEvent, pending = kind, time.Now(), true
				schedule()
				break
			}
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
				kind, watched := targets.files[filepath.Clean(event.Name)]
				if !watched {
					continue
				}
				changed, lastEvent, pending = kind, time.Now(), true
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
					p.reloadChanged(done, currentChange, filePath, xDnsPath, opts, &state, reload, rejected)
					select {
					case finished <- struct{}{}:
					case <-done:
					}
				}()
			case <-finished:
				active = false
				if updated, err := targets.update(filePath, xDnsPath, p); err != nil {
					log.Printf("File watcher error: %s", err)
				} else if updated && !pending {
					// Recheck edits that arrived before a new watch was attached.
					changed, lastEvent, pending = "config", time.Now(), true
				}
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
func (p *Conf) reloadChanged(done <-chan struct{}, changed, filePath, xDnsPath string, opts ValidateOptions, state *watchState, reload func() error, rejected func(error)) {
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
	var nextState watchState
	if err == nil {
		nextState, err = snapshotWatchState(next, xDnsPath)
	}
	if err == nil && !state.retry && state.equal(nextState) {
		return
	}
	var outbounds map[string]struct{}
	if err == nil && opts.ReloadOutbounds != nil {
		outbounds = state.changedOutbounds(nextState, next, xDnsPath)
		if len(outbounds) > 0 {
			err = opts.ReloadOutbounds(next, outbounds)
		}
	}
	if err == nil && len(outbounds) == 0 && opts.CheckReload != nil {
		err = opts.CheckReload(p, next)
	}
	if err != nil {
		if rejected != nil {
			rejected(err)
		} else {
			log.Printf("reload rejected, keeping the running config: %s", err)
		}
		return
	}
	if len(outbounds) > 0 {
		// Leave the main config and node objects in place. The live outbound
		// managers have accepted the new file contents.
		*state = nextState
		log.Println("reload outbound config success")
		return
	}
	log.Printf("%s file changed, reloading...", changed)
	*p = *next
	if err := reload(); err != nil {
		state.retry = true
		log.Printf("reload failed; the next file write will retry: %s", err)
		return
	}
	*state = nextState
	log.Println("reload config success")
}

type watchTargets struct {
	watcher   *fsnotify.Watcher
	files     map[string]string
	dirs      map[string]struct{}
	outbounds bool
}

// Watch parent directories so a save that replaces a file with a rename
// does not detach its watch. Filter events to the configured paths.
func (w *watchTargets) update(config, dns string, c *Conf) (bool, error) {
	files := make(map[string]string)
	dirs := make(map[string]struct{})
	addFile := func(path, kind string) {
		dir := filepath.Dir(path)
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			dir = resolved
		}
		files[filepath.Join(dir, filepath.Base(path))] = kind
		dirs[dir] = struct{}{}
	}
	add := func(path, kind string) {
		if path == "" {
			return
		}
		if absolute, err := filepath.Abs(path); err == nil {
			path = absolute
		}
		addFile(path, kind)
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			addFile(resolved, kind)
		}
	}
	for _, core := range c.CoresConfig {
		if x := core.XrayConfig; x != nil {
			if w.outbounds {
				add(x.OutboundConfigPath, "outbound")
			}
			add(x.RouteConfigPath, "route")
		}
	}
	add(dns, "DNS")
	add(config, "config")

	var added []string
	for dir := range dirs {
		if _, ok := w.dirs[dir]; ok {
			continue
		}
		if err := w.watcher.Add(dir); err != nil {
			for _, dir := range added {
				_ = w.watcher.Remove(dir)
			}
			return false, fmt.Errorf("watch directory %s: %w", dir, err)
		}
		added = append(added, dir)
	}
	for dir := range w.dirs {
		if _, keep := dirs[dir]; !keep {
			if err := w.watcher.Remove(dir); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
				log.Printf("File watcher error: %s", err)
			}
		}
	}
	updated := !maps.Equal(w.files, files)
	w.files, w.dirs = files, dirs
	return updated, nil
}
