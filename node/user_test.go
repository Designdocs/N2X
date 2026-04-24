package node

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
)

func TestCompareUserListTreatsDeviceLimitAsLimiterOnlyChange(t *testing.T) {
	oldUsers := []panel.UserInfo{{
		Id:          1,
		Uuid:        "uuid-1",
		SpeedLimit:  10,
		DeviceLimit: 1,
	}}
	newUsers := []panel.UserInfo{{
		Id:          1,
		Uuid:        "uuid-1",
		SpeedLimit:  10,
		DeviceLimit: 2,
	}}

	changes := compareUserList(oldUsers, newUsers)
	if len(changes.deleted) != 0 || len(changes.added) != 0 {
		t.Fatalf("core changes = deleted %d added %d, want none", len(changes.deleted), len(changes.added))
	}
	if len(changes.limiterDeleted) != 1 || len(changes.limiterAdded) != 1 {
		t.Fatalf("limiter changes = deleted %d added %d, want 1/1",
			len(changes.limiterDeleted),
			len(changes.limiterAdded))
	}
	if changes.limiterAdded[0].DeviceLimit != 2 {
		t.Fatalf("limiter added device limit = %d, want 2", changes.limiterAdded[0].DeviceLimit)
	}
}

func TestCompareUserListDetectsUUIDAddDelete(t *testing.T) {
	oldUsers := []panel.UserInfo{{Id: 1, Uuid: "old"}}
	newUsers := []panel.UserInfo{{Id: 2, Uuid: "new"}}

	changes := compareUserList(oldUsers, newUsers)
	if len(changes.deleted) != 1 || changes.deleted[0].Uuid != "old" {
		t.Fatalf("deleted = %+v, want old user", changes.deleted)
	}
	if len(changes.added) != 1 || changes.added[0].Uuid != "new" {
		t.Fatalf("added = %+v, want new user", changes.added)
	}
	if len(changes.limiterDeleted) != 1 || len(changes.limiterAdded) != 1 {
		t.Fatalf("limiter changes = deleted %d added %d, want 1/1",
			len(changes.limiterDeleted),
			len(changes.limiterAdded))
	}
}
