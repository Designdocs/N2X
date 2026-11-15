package panel

// The socket reader only signals; controller-owned serialization performs I/O.
func (c *Client) SetSyncWakeHook(hook func()) {
	c.etagMu.Lock()
	c.syncWake = hook
	c.etagMu.Unlock()
}

func (c *Client) wakeSync() {
	c.etagMu.Lock()
	hook := c.syncWake
	c.etagMu.Unlock()
	if hook != nil {
		hook()
	}
}
