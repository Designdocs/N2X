package panel

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Designdocs/N2X/common/domainusage"
)

type DomainQuery struct {
	ID   string
	UID  int
	Day  time.Time
	Live bool
}
type DomainControl struct {
	Paused atomic.Bool
	rate   atomic.Pointer[float64]
	query  atomic.Pointer[DomainQuery]
	Store  atomic.Pointer[domainusage.Store]
}

func (d *DomainControl) Header() string {
	if d.Paused.Load() {
		return "disabled"
	}
	return strconv.FormatBool(d.Store.Load() != nil)
}
func (d *DomainControl) ClearQuery()    { d.query.Store(nil) }
func (d *DomainControl) Rate() *float64 { return d.rate.Load() }
func parseDomainRate(value string) *float64 {
	rate, err := strconv.ParseFloat(value, 64)
	if err != nil || rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return nil
	}
	return &rate
}

func (d *DomainControl) observe(value string) {
	rate := parseDomainRate(value)
	if rate == nil {
		return
	}
	d.rate.Store(rate)
	if s := d.Store.Load(); s != nil {
		s.SetRate(time.Now(), *rate)
	}
}
func (d *DomainControl) offer(header string) {
	if d.Paused.Load() {
		return
	}
	fields := strings.Split(header, ",")
	live := len(fields) == 4 && fields[3] == "live"
	if (!live && len(fields) != 3) || len(fields[0]) != 36 {
		return
	}
	uid, err := strconv.Atoi(fields[1])
	day, e := time.Parse(time.DateOnly, fields[2])
	if err == nil && e == nil && uid > 0 {
		d.query.Store(&DomainQuery{ID: fields[0], UID: uid, Day: day, Live: live})
	}
}
func (c *Client) AnswerDomainQuery() error {
	store := c.Domains.Store.Load()
	if store == nil {
		return nil
	}
	q := c.Domains.query.Swap(nil)
	if q == nil {
		return nil
	}
	readPage := func(after *string) (domainusage.Page, error) { return store.QueryPage(q.UID, q.Day, after) }
	if q.Live {
		readPage = store.LivePages(q.UID, time.Now())
	}
	var after *string
	var version string
	attempt := strconv.FormatInt(time.Now().UnixNano(), 36)
	for i := 0; ; i++ {
		if store.Context().Err() != nil || c.Domains.Store.Load() != store {
			return nil
		}
		page, err := readPage(after)
		if err != nil {
			return err
		}
		if after != nil && page.Version != version {
			return domainusage.ErrSnapshotChanged
		}
		// Only the final page publishes this attempt. Earlier pages announce at
		// least one successor, so the panel can stage them without a counting pass.
		pages := i + 1
		if page.More {
			pages++
		}
		data := map[string]any{"id": q.ID, "attempt": attempt, "page": i, "pages": pages, "until": page.Until, "rows": page.Rows}
		const path = "/api/v1/server/UniProxy/domainUsage"
		r, err := c.client.R().SetContext(store.Context()).SetBody(data).Post(path)
		if err = c.checkResponse(r, path, err); err != nil {
			return fmt.Errorf("send domain usage page %d: %w", i, err)
		}
		if !page.More {
			return nil
		}
		version = page.Version
		after = &page.Rows[len(page.Rows)-1].Host
	}

}
func (d *DomainControl) HasQuery() bool { return d.query.Load() != nil }
