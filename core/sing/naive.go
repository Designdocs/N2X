package sing

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"sync"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	F "github.com/sagernet/sing/common/format"
)

// naiveState keeps the user set for each node. The listener starts with the
// first user; later changes replace authentication state without closing tunnels.
type naiveState struct {
	mu    sync.Mutex
	nodes map[string]*naiveNode
}

type naiveNode struct {
	info    *panel.NodeInfo
	options *conf.Options
	// users maps username to password. Both are the panel UUID, which is what
	// a naive client sends as its proxy credentials.
	users   map[string]string
	retired map[string]struct{}
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

// addNaiveUsers publishes a new user set without replacing a running inbound.
func (b *Sing) addNaiveUsers(tag string, users []panel.UserInfo) (int, error) {
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	node, ok := b.naive.nodes[tag]
	if !ok {
		return 0, fmt.Errorf("the naive node %s is not registered", tag)
	}
	updated := maps.Clone(node.users)
	changed := 0
	for i := range users {
		uuid := users[i].Uuid
		if existing, found := node.users[uuid]; found && existing == uuid {
			continue
		}
		updated[uuid] = uuid
		changed++
	}
	if changed == 0 {
		return len(users), nil
	}
	if err := b.updateNaiveUsersLocked(tag, node, updated); err != nil {
		return 0, err
	}
	return len(users), nil
}

// delNaiveUsers revokes future authentication and lets existing tunnels finish.
func (b *Sing) delNaiveUsers(tag string, users []panel.UserInfo) error {
	b.naive.mu.Lock()
	defer b.naive.mu.Unlock()
	node, ok := b.naive.nodes[tag]
	if !ok {
		return fmt.Errorf("the naive node %s is not registered", tag)
	}
	updated := maps.Clone(node.users)
	changed := 0
	for i := range users {
		if _, found := node.users[users[i].Uuid]; found {
			delete(updated, users[i].Uuid)
			changed++
		}
	}
	if changed == 0 {
		return nil
	}
	return b.updateNaiveUsersLocked(tag, node, updated)
}

// updateNaiveUsersLocked commits the user set only after it is applied.
// The caller holds naive.mu. An empty set keeps a started listener alive so
// authenticated HTTP/2 and HTTP/3 streams can finish without being reset.
func (b *Sing) updateNaiveUsersLocked(tag string, node *naiveNode, updated map[string]string) error {
	users := make([]auth.User, 0, len(updated))
	names := make([]string, 0, len(updated))
	for name := range updated {
		names = append(names, name)
	}
	// Keep credential snapshots deterministic.
	sort.Strings(names)
	for _, name := range names {
		users = append(users, auth.User{Username: name, Password: updated[name]})
	}

	if node.built {
		in, found := b.box.Inbound().Get(tag)
		if !found {
			return fmt.Errorf("the naive inbound %s is not found", tag)
		}
		updater, ok := in.(interface {
			UpdateUsers([]auth.User)
			UserActive(string) bool
		})
		if !ok {
			return fmt.Errorf("naive inbound %s does not support live user updates; existing connections kept", tag)
		}
		updater.UpdateUsers(users)
		node.commitUsers(updated)
		return nil
	}
	if len(users) == 0 {
		return nil
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
	node.commitUsers(updated)
	log.Info("[", tag, "] naive listener started with ", len(users), " users")
	return nil
}

// naiveUserActive includes pending routes as well as established tunnels.
func (b *Sing) naiveUserActive(tag, user string) bool {
	in, found := b.box.Inbound().Get(tag)
	if !found {
		return false
	}
	if tracker, ok := in.(interface{ UserActive(string) bool }); ok {
		return tracker.UserActive(user)
	}
	// An older core cannot prove it is safe to retire a user's accounting.
	return true
}

func (n *naiveNode) commitUsers(updated map[string]string) {
	if n.retired == nil {
		n.retired = make(map[string]struct{})
	}
	for user := range n.users {
		if _, present := updated[user]; !present {
			n.retired[user] = struct{}{}
		}
	}
	for user := range updated {
		delete(n.retired, user)
	}
	n.users = updated
}
