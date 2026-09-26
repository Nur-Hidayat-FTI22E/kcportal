package netctl

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	guestMAC  = mustMAC("aa:bb:cc:dd:ee:01")
	guestMAC2 = mustMAC("aa:bb:cc:dd:ee:02")
)

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic("test fixture: bad MAC " + s + ": " + err.Error())
	}
	return mac
}

// TestMockCompileTimeInterface guard: Mock must keep satisfying the IF-01
// contract — the reason the real NetCtl (nft/netlink) can slot in later
// without touching callers (cmd/kcportald wires exactly this).
var (
	_ NetCtl = (*Mock)(nil)
)

func TestMockAuthorizeAndRevoke(t *testing.T) {
	m := NewMock()

	if m.GuestCount() != 0 {
		t.Fatalf("fresh mock has %d guests, want 0", m.GuestCount())
	}
	if m.IsAuthorized(guestMAC) {
		t.Fatal("fresh mock reports an unseeded MAC as authorized")
	}

	if err := m.AuthorizeGuest(guestMAC, time.Minute); err != nil {
		t.Fatalf("AuthorizeGuest: %v", err)
	}
	if !m.IsAuthorized(guestMAC) {
		t.Fatal("MAC not authorized right after AuthorizeGuest")
	}
	if m.GuestCount() != 1 {
		t.Fatalf("GuestCount = %d, want 1", m.GuestCount())
	}

	if err := m.RevokeGuest(guestMAC); err != nil {
		t.Fatalf("RevokeGuest: %v", err)
	}
	if m.IsAuthorized(guestMAC) {
		t.Fatal("MAC still authorized after RevokeGuest")
	}
	if m.GuestCount() != 0 {
		t.Fatalf("GuestCount = %d after revoke, want 0", m.GuestCount())
	}
}

// TestMockAuthorizeIsIdempotentRefresh pins the doc comment on the
// interface: re-authorizing "just refreshes the timeout" — it must not
// create a second entry (authed_guests is a set keyed by MAC).
func TestMockAuthorizeIsIdempotentRefresh(t *testing.T) {
	m := NewMock()

	if err := m.AuthorizeGuest(guestMAC, time.Minute); err != nil {
		t.Fatalf("first AuthorizeGuest: %v", err)
	}
	if err := m.AuthorizeGuest(guestMAC, 2*time.Minute); err != nil {
		t.Fatalf("second AuthorizeGuest: %v", err)
	}
	if m.GuestCount() != 1 {
		t.Fatalf("GuestCount = %d after double-authorize, want 1 (set semantics)", m.GuestCount())
	}
	if !m.IsAuthorized(guestMAC) {
		t.Fatal("MAC lost authorization after refresh")
	}
}

// TestMockGuestCountIgnoresExpired: GuestCount only counts MACs whose
// timeout is still in the future; IsAuthorized agrees with it.
func TestMockGuestCountIgnoresExpired(t *testing.T) {
	m := NewMock()

	if err := m.AuthorizeGuest(guestMAC, 20*time.Millisecond); err != nil {
		t.Fatalf("AuthorizeGuest: %v", err)
	}
	if err := m.AuthorizeGuest(guestMAC2, time.Minute); err != nil {
		t.Fatalf("AuthorizeGuest: %v", err)
	}
	if m.GuestCount() != 2 {
		t.Fatalf("GuestCount = %d, want 2", m.GuestCount())
	}

	time.Sleep(50 * time.Millisecond) // let the short TTL lapse

	if m.IsAuthorized(guestMAC) {
		t.Fatal("expired MAC still reported authorized")
	}
	if m.IsAuthorized(guestMAC2) != true {
		t.Fatal("long-TTL MAC should still be authorized")
	}
	if got := m.GuestCount(); got != 1 {
		t.Fatalf("GuestCount = %d after expiry, want 1", got)
	}
}

func TestMockRevokeUnknownMACIsNoop(t *testing.T) {
	m := NewMock()
	if err := m.RevokeGuest(guestMAC); err != nil {
		t.Fatalf("RevokeGuest on unknown MAC must be a nil-error noop, got %v", err)
	}
}

func TestMockLookupNeighbor(t *testing.T) {
	m := NewMock()
	ip := netip.MustParseAddr("10.20.3.44")

	// Unseeded lookups must fail — DD-10 makes the neighbor table the only
	// trusted identity source, so a silent empty answer would be a bug.
	if _, err := m.LookupNeighbor("br-guest", ip); err == nil {
		t.Fatal("LookupNeighbor on an unseeded entry must return an error")
	}

	m.SeedNeighbor("br-guest", ip, guestMAC)
	got, err := m.LookupNeighbor("br-guest", ip)
	if err != nil {
		t.Fatalf("LookupNeighbor: %v", err)
	}
	if !bytes.Equal(got, guestMAC) {
		t.Fatalf("LookupNeighbor = %s, want %s", got, guestMAC)
	}

	// Entries are scoped per interface: same IP on another iface is still
	// unknown (a guest on br-guest must not be confused with br-lan).
	if _, err := m.LookupNeighbor("br-lan", ip); err == nil {
		t.Fatal("seeded neighbor leaked across interfaces")
	}
}

func TestMockLookupNeighborIPv6(t *testing.T) {
	m := NewMock()
	ip6 := netip.MustParseAddr("fd00:20::44")

	m.SeedNeighbor("br-guest", ip6, guestMAC2)
	got, err := m.LookupNeighbor("br-guest", ip6)
	if err != nil {
		t.Fatalf("LookupNeighbor ipv6: %v", err)
	}
	if !bytes.Equal(got, guestMAC2) {
		t.Fatalf("LookupNeighbor = %s, want %s", got, guestMAC2)
	}
}

// TestMockBound: SEC-012 anti-spoof — Bound is true only for the exact
// learned (MAC, IP) pairing, not for any recombination.
func TestMockBound(t *testing.T) {
	m := NewMock()
	ip := netip.MustParseAddr("10.20.3.44")
	other := netip.MustParseAddr("10.20.3.99")

	m.SeedBinding(guestMAC, ip)

	if !m.Bound(guestMAC, ip) {
		t.Fatal("Bound false for the exact seeded pairing")
	}
	if m.Bound(guestMAC, other) {
		t.Fatal("Bound true for a different IP — anti-spoof broken")
	}
	if m.Bound(guestMAC2, ip) {
		t.Fatal("Bound true for a different MAC — anti-spoof broken")
	}
	if m.Bound(guestMAC2, other) {
		t.Fatal("Bound true for an unseeded pairing")
	}
}

// TestMockConcurrentAccess exercises the mutex under -race: the mock is
// shared by the actor goroutine and test code in real usage.
func TestMockConcurrentAccess(t *testing.T) {
	m := NewMock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = m.AuthorizeGuest(guestMAC, time.Minute)
				_ = m.IsAuthorized(guestMAC)
				_ = m.GuestCount()
				_ = m.Bound(guestMAC, netip.MustParseAddr("10.20.3.44"))
				_, _ = m.LookupNeighbor("br-guest", netip.MustParseAddr("10.20.3.44"))
				_ = m.RevokeGuest(guestMAC)
				m.SeedNeighbor("br-guest", netip.MustParseAddr("10.20.3.44"), guestMAC)
				m.SeedBinding(guestMAC, netip.MustParseAddr("10.20.3.44"))
			}
		}()
	}
	wg.Wait()
}
