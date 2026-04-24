package node

import "github.com/Designdocs/N2X/api/panel"

type userListChanges struct {
	deleted        []panel.UserInfo
	added          []panel.UserInfo
	limiterDeleted []panel.UserInfo
	limiterAdded   []panel.UserInfo
}

func compareUserList(old, new []panel.UserInfo) userListChanges {
	oldByUUID := make(map[string]panel.UserInfo, len(old))
	for _, user := range old {
		oldByUUID[user.Uuid] = user
	}

	var changes userListChanges
	for _, user := range new {
		oldUser, exists := oldByUUID[user.Uuid]
		if !exists {
			changes.added = append(changes.added, user)
			changes.limiterAdded = append(changes.limiterAdded, user)
			continue
		}
		if userLimitFieldsChanged(oldUser, user) {
			changes.limiterDeleted = append(changes.limiterDeleted, oldUser)
			changes.limiterAdded = append(changes.limiterAdded, user)
		}
		delete(oldByUUID, user.Uuid)
	}

	for _, user := range oldByUUID {
		changes.deleted = append(changes.deleted, user)
		changes.limiterDeleted = append(changes.limiterDeleted, user)
	}

	return changes
}

func userLimitFieldsChanged(old, new panel.UserInfo) bool {
	return old.Id != new.Id ||
		old.SpeedLimit != new.SpeedLimit ||
		old.DeviceLimit != new.DeviceLimit
}
