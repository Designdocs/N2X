package domainusage

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"
)

// StorageUsage returns quota usage and available bytes on the statistics volume.
// An unavailable measurement is -1. Reading the menu never creates a directory.
func StorageUsage(dir string) (used, free int64) {
	_, used, err := quotaInventory(dir, "")
	if err != nil && !os.IsNotExist(err) {
		used = -1
	}
	for {
		free, err = FreeBytes(dir)
		if err == nil {
			return used, free
		}
		parent := filepath.Dir(dir)
		if !os.IsNotExist(err) || parent == dir {
			return used, -1
		}
		dir = parent
	}
}

type InstanceState struct {
	Panel string
	Node  int
	State string
}

func InstanceStates(dir string) []InstanceState {
	var results []InstanceState
	deadline := time.Now().Add(2 * time.Second)
	err := visitLocal(dir, 250*time.Millisecond, func(c net.Conn) error {
		// A busy or older collector must not prevent the menu from opening.
		end := time.Now().Add(400 * time.Millisecond)
		if end.After(deadline) {
			end = deadline
		}
		c.SetDeadline(end)
		var reply localReply
		if err := json.NewEncoder(c).Encode(localQuery{Status: true}); err == nil {
			if err = json.NewDecoder(c).Decode(&reply); err != nil {
				reply = localReply{}
			}
		}
		results = append(results, InstanceState{Panel: reply.Panel, Node: reply.Node, State: reply.State})
		return nil
	})
	if err != nil {
		results = append(results, InstanceState{})
	}
	return results
}
