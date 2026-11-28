package dispatcher

import (
	"context"
	"github.com/Designdocs/N2X/common/counter"
	"sync/atomic"
	"time"

	"github.com/Designdocs/N2X/common/rate"
	"github.com/xtls/xray-core/common/buf"
)

var _ buf.TimeoutReader = (*CounterReader)(nil)

type CounterReader struct {
	Reader  buf.TimeoutReader
	Counter *atomic.Int64
	Domain  *counter.DomainCounter
	Limiter *rate.Controller
	Context context.Context
}

func (c *CounterReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBufferTimeout(timeout)
	return c.finishRead(mb, err)
}

func (c *CounterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBuffer()
	return c.finishRead(mb, err)
}

func (c *CounterReader) finishRead(mb buf.MultiBuffer, err error) (buf.MultiBuffer, error) {
	if n := int64(mb.Len()); n > 0 {
		if c.Limiter != nil {
			if waitErr := c.Limiter.Wait(c.Context, n); waitErr != nil {
				buf.ReleaseMulti(mb)
				return nil, waitErr
			}
			c.Limiter.Account(n)
		}
		c.Domain.Add(n)
		c.Counter.Add(n)
	}
	return mb, err
}
