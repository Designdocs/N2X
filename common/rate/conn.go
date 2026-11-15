package rate

import (
	"context"
	"io"
	"net"
)

func NewConnRateLimiter(c net.Conn, l *Controller, parent context.Context) *Conn {
	ctx, cancel := context.WithCancel(parent)
	return &Conn{
		Conn:    c,
		limiter: l,
		ctx:     ctx,
		cancel:  cancel,
	}
}

type Conn struct {
	net.Conn
	limiter *Controller
	ctx     context.Context
	cancel  context.CancelFunc
}

func (c *Conn) Close() error { c.cancel(); return c.Conn.Close() }

func (c *Conn) Read(b []byte) (n int, err error) {
	chunkSize := 65536
	if c.limiter.Rate() > 0 {
		chunkSize = 16384
	}
	b = b[:min(len(b), chunkSize)]
	n, err = c.Conn.Read(b)
	if n > 0 {
		if waitErr := c.limiter.Wait(c.ctx, int64(n)); waitErr != nil {
			return n, waitErr
		}
		c.limiter.Account(int64(n))
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	for len(b) > 0 {
		chunkSize := 65536
		if c.limiter.Rate() > 0 {
			chunkSize = 16384
		}
		chunk := b[:min(len(b), chunkSize)]
		if err = c.limiter.Wait(c.ctx, int64(len(chunk))); err != nil {
			return n, err
		}
		written, writeErr := c.Conn.Write(chunk)
		if written > 0 {
			c.limiter.Account(int64(written))
			n += written
			b = b[written:]
		}
		if writeErr != nil {
			return n, writeErr
		}
		if written == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, err
}
