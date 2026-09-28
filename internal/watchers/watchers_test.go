// Package-level tests for the watcher packages live in this shared
// file: it belongs to package neighbors_test and imports dhcphook the
// same way a user would — the two watchers never depend on each other,
// but testing them side by side keeps the cross-package contracts
// (Provider/Entry shapes) honest in one place.
package watchers_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"kotacloud-portal/internal/watchers/dhcphook"
	"kotacloud-portal/internal/watchers/neighbors"
)

// --- dhcphook: real unix-socket round trip ---

func TestDHCPHookEndToEnd(t *testing.T) {
	dir := t.TempDir()
	events := make(chan dhcphook.Event, 8)
	w := dhcphook.New(dir, func(ev dhcphook.Event) { events <- ev },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- w.Run(ctx) }()

	// Wait for the socket to appear.
	sock := filepath.Join(dir, "hook.sock")
	deadline := time.Now().Add(2 * time.Second)
	for !dialable(sock) {
		if time.Now().After(deadline) {
			t.Fatal("hook.sock never became dialable")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Emulate dhcp-hook: one JSON line per event.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	enc := json.NewEncoder(conn)
	for _, ev := range []dhcphook.Event{
		{Action: "add", MAC: "AA:BB:CC:DD:0F:01", IP: "10.20.2.11", Hostname: "tablet-kasir", Interface: "br-lan"},
		{Action: "old", MAC: "aa:bb:cc:dd:0f:01", IP: "10.20.2.11", Interface: "br-lan"},
		{Action: "bogus", MAC: "aa:bb:cc:dd:0f:02", IP: "10.20.2.12"}, // malformed: dropped by the watcher
		{Action: "del", MAC: "aa:bb:cc:dd:0f:01", IP: "10.20.2.11"},
	} {
		if err := enc.Encode(ev); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	conn.Close()

	read := func() dhcphook.Event {
		select {
		case ev := <-events:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for a lease event")
			return dhcphook.Event{}
		}
	}
	first := read()
	if first.Action != "add" || first.MAC != "aa:bb:cc:dd:0f:01" || first.Hostname != "tablet-kasir" {
		t.Errorf("first event = %+v", first)
	}
	second := read()
	if second.Action != "old" || second.Hostname != "" {
		t.Errorf("second event = %+v (bogus action must be filtered, not passed through)", second)
	}
	third := read()
	if third.Action != "del" {
		t.Errorf("third event = %+v", third)
	}
	if len(events) != 0 {
		t.Errorf("malformed event leaked through: %+v", <-events)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func dialable(sock string) bool {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// --- neighbors: cache semantics with a fake provider ---

type fakeProvider struct {
	rows   []neighbors.Entry
	calls  int
	stamps []time.Time
}

func (f *fakeProvider) ListNeighbors() []neighbors.Entry {
	f.calls++
	if len(f.stamps) > 0 {
		s := f.stamps[0]
		f.stamps = f.stamps[1:]
		for i := range f.rows {
			f.rows[i].Seen = s
		}
	}
	return f.rows
}

func TestNeighborCacheRefreshAndLookup(t *testing.T) {
	ip := netip.MustParseAddr("10.20.3.44")
	fp := &fakeProvider{}
	c := neighbors.NewCache(fp, time.Minute)

	// Empty provider: no entries.
	c.Refresh()
	if c.Len() != 0 {
		t.Fatalf("cache = %d entries with an empty provider", c.Len())
	}
	if _, ok := c.MACForIP(ip); ok {
		t.Fatal("lookup on empty cache must miss")
	}

	fp.rows = []neighbors.Entry{{IP: ip, MAC: "aa:bb:cc:dd:0f:03", Interface: "br-guest"}}
	c.Refresh()
	mac, ok := c.MACForIP(ip)
	if !ok || mac != "aa:bb:cc:dd:0f:03" {
		t.Fatalf("MACForIP = %q %v, want the seeded MAC", mac, ok)
	}
	if fp.calls < 2 {
		t.Errorf("provider called %d times, want >=2", fp.calls)
	}
}

func TestNeighborCacheTTLExpiry(t *testing.T) {
	ip := netip.MustParseAddr("10.20.3.45")
	now := time.Unix(1_700_000_000, 0)
	fp := &fakeProvider{}
	c := neighbors.NewCache(fp, 30*time.Second)
	c.SetNowForTest(func() time.Time { return now })

	fp.rows = []neighbors.Entry{{IP: ip, MAC: "aa:bb:cc:dd:0f:04", Interface: "br-guest", Seen: now}}
	c.Refresh()
	if _, ok := c.MACForIP(ip); !ok {
		t.Fatal("fresh entry must hit")
	}

	// Advance past the TTL without a refresh: lookup drops the stale entry.
	c.SetNowForTest(func() time.Time { return now.Add(31 * time.Second) })
	if _, ok := c.MACForIP(ip); ok {
		t.Fatal("stale entry must miss")
	}
	if c.Len() != 0 {
		t.Fatalf("stale entry not evicted, cache holds %d", c.Len())
	}
}

func TestNeighborCacheRunStopsOnCancel(t *testing.T) {
	fp := &fakeProvider{}
	c := neighbors.NewCache(fp, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
