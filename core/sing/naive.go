package sing

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	F "github.com/sagernet/sing/common/format"
)

// naiveState owns the NaiveProxy nodes.
//
// Unlike every other protocol in this core, sing-box's naive inbound has no
// live user-management API: its authenticator is built once, at construction,
// from a fixed user list, and it refuses to start with an empty one. So a
// naive node keeps its user set here and the inbound is rebuilt whenever that
// set changes. Rebuilding re-binds the listener, which drops connections that
// are in flight — acceptable because it only happens when the panel actually
// adds or removes a user on this node, not on every sync.
type naiveState struct {
	mu    sync.Mutex
	nodes map[string]*naiveNode
}

type naiveNode struct {
	info    *panel.NodeInfo
	options *conf.Options
	// users maps username to password. Both are the panel UUID, which is what
	// a naive client sends as its proxy credentials.
	users map[string]string
	// built records whether an inbound currently exists for this node.
	built bool
}

func newNaiveState() *naiveState {
	return &naiveState{nodes: make(map[string]*naiveNode)}
}

// register records a naive node. No inbound is created yet: naive needs at
// least one user, which only arrives with the first AddUsers call.
func (b *Sing) registerNaiveNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	if info.Naive == nil {
		return fmt.Errorf("missing naive node settings")
	}
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	b.naive.nodes[tag] = &naiveNode{
		info:    info,
		options: options,
		users:   make(map[string]string),
	}
	return nil
}

// unregisterNaiveNode drops the node's state and removes its inbound.
func (b *Sing) unregisterNaiveNode(tag string) error {
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	node, ok := b.naive.nodes[tag]
	if !ok {
		return nil
	}
	delete(b.naive.nodes, tag)
	if !node.built {
		return nil
	}
	if err := b.box.Inbound().Remove(tag); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("remove naive inbound: %w", err)
	}
	return nil
}

// addNaiveUsers adds users and rebuilds the inbound if the set changed.
func (b *Sing) addNaiveUsers(tag string, users []panel.UserInfo) (int, error) {
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	node, ok := b.naive.nodes[tag]
	if !ok {
		return 0, fmt.Errorf("the naive node %s is not registered", tag)
	}
	changed := 0
	for i := range users {
		uuid := users[i].Uuid
		if existing, found := node.users[uuid]; found && existing == uuid {
			continue
		}
		node.users[uuid] = uuid
		changed++
	}
	if changed == 0 {
		return len(users), nil
	}
	if err := b.rebuildNaiveLocked(tag, node); err != nil {
		return 0, err
	}
	return len(users), nil
}

// delNaiveUsers removes users and rebuilds the inbound if the set changed.
func (b *Sing) delNaiveUsers(tag string, users []panel.UserInfo) error {
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	node, ok := b.naive.nodes[tag]
	if !ok {
		return fmt.Errorf("the naive node %s is not registered", tag)
	}
	changed := 0
	for i := range users {
		if _, found := node.users[users[i].Uuid]; found {
			delete(node.users, users[i].Uuid)
			changed++
		}
	}
	if changed == 0 {
		return nil
	}
	return b.rebuildNaiveLocked(tag, node)
}

// rebuildNaiveLocked recreates the node's inbound from its current user set.
// The caller must hold naive.mu.
//
// The existing inbound is removed before the replacement is created: the
// inbound manager starts a new inbound before closing the one it replaces, so
// creating first would fail to bind the port that is still in use.
func (b *Sing) rebuildNaiveLocked(tag string, node *naiveNode) error {
	if node.built {
		if err := b.box.Inbound().Remove(tag); err != nil && !errors.Is(err, os.ErrInvalid) {
			return fmt.Errorf("remove naive inbound: %w", err)
		}
		node.built = false
	}
	if len(node.users) == 0 {
		// Naive cannot run without users; leave the port closed until one
		// arrives rather than starting a listener that rejects everyone.
		log.Info("[", tag, "] naive has no users, listener stopped")
		return nil
	}

	users := make([]auth.User, 0, len(node.users))
	names := make([]string, 0, len(node.users))
	for name := range node.users {
		names = append(names, name)
	}
	// Deterministic ordering keeps the generated inbound stable across
	// rebuilds, which makes the logs readable and the behaviour reproducible.
	sort.Strings(names)
	for _, name := range names {
		users = append(users, auth.User{Username: name, Password: node.users[name]})
	}

	options, err := buildNaiveOptions(node.info, node.options, users)
	if err != nil {
		return err
	}
	err = b.box.Inbound().Create(
		b.ctx,
		b.router,
		b.logFactory.NewLogger(F.ToString("inbound/naive[", tag, "]")),
		tag,
		"naive",
		options,
	)
	if err != nil {
		return fmt.Errorf("create naive inbound: %w", err)
	}
	node.built = true
	log.Info("[", tag, "] naive listener rebuilt with ", len(users), " users")
	return nil
}
