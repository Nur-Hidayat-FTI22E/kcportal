// Package neighbors keeps the live in-memory view of the kernel's
// neighbor (ARP/ND) tables — the DD-03/D-10 source of truth for mapping
// source IPs back to MACs and for learning IPv6 bindings that dnsmasq
// leases cannot provide. The netlink subscriber (rtnetlink RTM_GETNEIGH/
// RTM_NEWNEIGH) lands with the real NetCtl in M2; until then the cache
// is fed from a snapshot provider, which the Mock and the integration
// wiring both implement.
package neighbors

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Entry is one learned neighbor: an IP reachable at a MAC on an
// interface, with the time we last saw it confirmed.
type Entry struct {
	IP        netip.Addr
	MAC       string
	Interface string
	Seen      time.Time
}

// Provider dumps the current neighbor table (all interfaces). It is the
// seam the real netlink implementation plugs into (and the Mock
// emulates: netctl.Mock implements it via ListLiveNeighbors).
type Provider interface {
	ListNeighbors() []Entry
}

// ProviderFunc adapts a function to Provider.
type ProviderFunc func() []Entry

// ListNeighbors implements Provider.
func (f ProviderFunc) ListNeighbors() []Entry { return f() }

// Adapt maps a provider returning foreign row types (e.g. netctl.Mock's
// LiveNeighbor) onto this package's Entry.
func Adapt[T any](rows []T, conv func(T) Entry) []Entry {
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, conv(r))
	}
	return out
}

// Cache is the goroutine-safe live table. It is intentionally in-memory
// (PD-4: derived state lives in RAM) and rebuilt/refreshed from the
// Provider on demand — losing it costs one refresh, nothing durable.
type Cache struct {
	mu    sync.RWMutex
	byIP  map[netip.Addr]Entry
	ttl   time.Duration
	prov  Provider
	nowFn func() time.Time
}

// NewCache builds a cache that refreshes from prov and forgets entries
// older than ttl (kernel entries vanish with their own timeout; our
// staleness bound just bounds memory).
func NewCache(prov Provider, ttl time.Duration) *Cache {
	return &Cache{
		byIP:  make(map[netip.Addr]Entry),
		ttl:   ttl,
		prov:  prov,
		nowFn: time.Now,
	}
}

// Merge folds pushed updates (the rtnetlink RTM_NEWNEIGH stream) into
// the cache without a poll round trip. It is a pure gain: only zero-Seen
// timestamps get stamped, and a nil/tombstone MAC removes the IP — the
// next full Refresh from the Provider remains authoritative. Safe for
// concurrent use.
func (c *Cache) Merge(entries ...Entry) {
	if len(entries) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range entries {
		if e.Seen.IsZero() {
			e.Seen = c.nowFn()
		}
		if e.MAC == "" {
			delete(c.byIP, e.IP)
		} else {
			c.byIP[e.IP] = e
		}
	}
}

// Refresh repopulates the cache from the provider, dropping entries not
// seen anymore. Safe for concurrent use.
func (c *Cache) Refresh() {
	if c.prov == nil {
		return
	}
	next := make(map[netip.Addr]Entry, len(c.byIP))
	for _, e := range c.prov.ListNeighbors() {
		if e.Seen.IsZero() {
			e.Seen = c.nowFn()
		}
		next[e.IP] = e
	}
	c.mu.Lock()
	c.byIP = next
	c.mu.Unlock()
}

// Lookup resolves ip → MAC (DD-10 seam used by portal-edge in M3). A
// stale entry is dropped and reported as not-found; the caller's next
// Refresh picks the table back up.
func (c *Cache) Lookup(ip netip.Addr) (Entry, bool) {
	c.mu.RLock()
	e, ok := c.byIP[ip]
	c.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if c.nowFn().Sub(e.Seen) > c.ttl {
		c.mu.Lock()
		delete(c.byIP, ip)
		c.mu.Unlock()
		return Entry{}, false
	}
	return e, true
}

// MACForIP is the narrow form of Lookup portal-edge needs.
func (c *Cache) MACForIP(ip netip.Addr) (string, bool) {
	e, ok := c.Lookup(ip)
	if !ok {
		return "", false
	}
	return e.MAC, true
}

// Len reports the number of currently cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byIP)
}

// SetNowForTest overrides the cache clock (TTL tests).
func (c *Cache) SetNowForTest(now func() time.Time) { c.nowFn = now }

// Run is the supervisor task shape: refresh on the given cadence until
// ctx ends. (The design's "neighbor watcher" cadence: fast enough for a
// ≤2 s detection budget, cheap enough for a Pi — 5 s it is.)
func (c *Cache) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	c.Refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Refresh()
		}
	}
}
