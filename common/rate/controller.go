package rate

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Controller is shared by every connection and direction of one identity.
// Connections retain this handle even while unlimited. No future tokens are
// reserved: a policy change wakes waiters and rechecks the current budget.
type Controller struct {
	mu      sync.Mutex
	rate    int64
	tokens  float64
	last    time.Time
	changed chan struct{}
	total   atomic.Int64
	closed  bool
}

func NewController(bytesPerSecond int64) *Controller {
	c := &Controller{last: time.Now(), changed: make(chan struct{})}
	c.SetRate(bytesPerSecond)
	return c
}

func (c *Controller) SetRate(bytesPerSecond int64) {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.rate == bytesPerSecond {
		return
	}
	c.refill(time.Now())
	wasUnlimited := c.rate == 0
	c.rate = bytesPerSecond
	if wasUnlimited {
		c.tokens = 0
	}
	c.tokens = math.Min(c.tokens, c.burst())
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *Controller) Rate() int64  { c.mu.Lock(); defer c.mu.Unlock(); return c.rate }
func (c *Controller) Total() int64 { return c.total.Load() }
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.changed)
	}
}
func (c *Controller) Account(n int64) {
	if n > 0 {
		c.total.Add(n)
	}
}

func (c *Controller) burst() float64 {
	return math.Max(16384, math.Min(float64(c.rate)/10, 65536))
}

func (c *Controller) refill(now time.Time) {
	c.tokens = math.Min(c.burst(), c.tokens+now.Sub(c.last).Seconds()*float64(c.rate))
	c.last = now
}

func (c *Controller) Wait(ctx context.Context, count int64) error {
	for count > 0 {
		n := min(count, int64(16384))
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return context.Canceled
			}
			if c.rate == 0 {
				c.mu.Unlock()
				return nil
			}
			c.refill(time.Now())
			if c.tokens >= float64(n) {
				c.tokens -= float64(n)
				c.mu.Unlock()
				break
			}
			delay := time.Duration(math.Ceil((float64(n) - c.tokens) * float64(time.Second) / float64(c.rate)))
			changed := c.changed
			c.mu.Unlock()
			timer := time.NewTimer(max(delay, time.Microsecond))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-changed:
				timer.Stop()
			case <-timer.C:
			}
		}
		count -= n
	}
	return nil
}
