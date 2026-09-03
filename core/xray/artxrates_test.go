package xray

import (
	"sync"
	"testing"
)

func TestArtXUserRateTableMergesTags(t *testing.T) {
	table := &artXUserRateTable{}

	table.set("node-a", map[string]uint64{"node-a|uuid-1": 125000})
	table.set("node-b", map[string]uint64{"node-b|uuid-2": 250000})

	if got := table.lookup("node-a|uuid-1"); got != 125000 {
		t.Fatalf("lookup(node-a|uuid-1) = %d, want 125000", got)
	}
	if got := table.lookup("node-b|uuid-2"); got != 250000 {
		t.Fatalf("lookup(node-b|uuid-2) = %d, want 250000", got)
	}
	if got := table.lookup("node-c|uuid-3"); got != 0 {
		t.Fatalf("lookup of unknown user = %d, want 0 (unlimited)", got)
	}
}

func TestArtXUserRateTableReplacesTagWholesale(t *testing.T) {
	table := &artXUserRateTable{}

	table.set("node-a", map[string]uint64{"node-a|uuid-1": 125000, "node-a|uuid-2": 125000})
	table.set("node-a", map[string]uint64{"node-a|uuid-2": 375000})

	if got := table.lookup("node-a|uuid-1"); got != 0 {
		t.Fatalf("dropped user still resolves to %d, want 0", got)
	}
	if got := table.lookup("node-a|uuid-2"); got != 375000 {
		t.Fatalf("lookup(node-a|uuid-2) = %d, want 375000", got)
	}
}

func TestArtXUserRateTableClearRemovesOnlyThatTag(t *testing.T) {
	table := &artXUserRateTable{}
	table.set("node-a", map[string]uint64{"node-a|uuid-1": 125000})
	table.set("node-b", map[string]uint64{"node-b|uuid-2": 125000})

	table.clear("node-a")

	if got := table.lookup("node-a|uuid-1"); got != 0 {
		t.Fatalf("cleared tag still resolves to %d, want 0", got)
	}
	if got := table.lookup("node-b|uuid-2"); got != 125000 {
		t.Fatalf("untouched tag = %d, want 125000", got)
	}
}

// The lookup runs on the ArtX accept path, so it must never take the write
// lock. This exercises the snapshot swap under concurrent publication.
func TestArtXUserRateTableLookupIsSafeUnderConcurrentUpdates(t *testing.T) {
	table := &artXUserRateTable{}
	table.set("node-a", map[string]uint64{"node-a|uuid-1": 125000})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			table.set("node-a", map[string]uint64{"node-a|uuid-1": uint64(125000 + i)})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = table.lookup("node-a|uuid-1")
		}
	}()
	wg.Wait()
}

func TestArtXUserRateTableLookupBeforeFirstPublication(t *testing.T) {
	table := &artXUserRateTable{}
	if got := table.lookup("node-a|uuid-1"); got != 0 {
		t.Fatalf("empty table = %d, want 0", got)
	}
}
