package rate

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	writer  buf.Writer
	limiter *Controller
	ctx     context.Context
}

func NewRateLimitWriter(writer buf.Writer, limiter *Controller, ctx context.Context) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for len(mb) > 0 {
		var chunk buf.MultiBuffer
		chunkSize := int32(65536)
		if w.limiter.Rate() > 0 {
			chunkSize = 16384
		}
		// A buffer may hold one UDP datagram and its destination metadata.
		// Split only between buffers so rate limiting never fragments it.
		mb, chunk = buf.SplitSize(mb, max(chunkSize, mb[0].Len()))
		n := int64(chunk.Len())
		if err := w.limiter.Wait(w.ctx, n); err != nil {
			buf.ReleaseMulti(chunk)
			buf.ReleaseMulti(mb)
			return err
		}
		if err := w.writer.WriteMultiBuffer(chunk); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		w.limiter.Account(n)
	}
	return nil
}
