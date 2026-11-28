package counter

import (
	"sync/atomic"

	"github.com/Designdocs/N2X/common/domainusage"
)

// Xray can accept client bytes before sniffing finishes and reveals the target.
type DomainCounter struct {
	target atomic.Pointer[domainusage.Flow]
	early  atomic.Int64
}

func (d *DomainCounter) Bind(f *domainusage.Flow) {
	d.target.Store(f)
	f.Bytes.Add(d.early.Swap(0))
}
func (d *DomainCounter) Add(n int64) {
	if d == nil {
		return
	}
	if f := d.target.Load(); f != nil {
		f.Bytes.Add(n)
		return
	}
	d.early.Add(n)
	if f := d.target.Load(); f != nil {
		f.Bytes.Add(d.early.Swap(0))
	}
}
