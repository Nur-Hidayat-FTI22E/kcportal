package netctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records invocations and serves canned output per command.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	output map[string]string
	errFor map[string]error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if e, ok := f.errFor[key]; ok {
		return f.output[key], e
	}
	return f.output[key], nil
}

func (f *fakeRunner) ran(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// fakeBroker records authorize/revoke calls.
type fakeBroker struct {
	mu   sync.Mutex
	auth map[string]time.Duration
	revs []string
	err  error
}

func (b *fakeBroker) Authorize(_ context.Context, mac string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.auth[mac] = ttl
	return nil
}

func (b *fakeBroker) Revoke(_ context.Context, mac string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.revs = append(b.revs, mac)
	delete(b.auth, mac)
	return nil
}

func newTestReal() (*Real, *fakeRunner, *fakeBroker) {
	fr := &fakeRunner{output: map[string]string{}, errFor: map[string]error{}}
	fb := &fakeBroker{auth: map[string]time.Duration{}}
	r := NewReal(fb, "br-guest")
	r.Runner = fr
	return r, fr, fb
}

var (
	guestMAC3 = mustMAC("aa:bb:cc:dd:11:01")
	guestIP3  = netip.MustParseAddr("10.20.3.44")
)

func TestRealAuthorizeGoesThroughBroker(t *testing.T) {
	r, fr, fb := newTestReal()

	if err := r.AuthorizeGuest(guestMAC3, time.Hour); err != nil {
		t.Fatalf("AuthorizeGuest: %v", err)
	}
	if got := fb.auth[guestMAC3.String()]; got != time.Hour {
		t.Fatalf("broker ttl = %v, want 1h (single-writer: the actor owns the set)", got)
	}
	if fr.ran("nft ") {
		t.Error("authorize must not touch nft directly (§7.3: via state actor)")
	}

	// Contract guards.
	if err := r.AuthorizeGuest(nil, time.Hour); err == nil {
		t.Error("nil MAC must fail")
	}
	if err := r.AuthorizeGuest(guestMAC3, 0); err == nil {
		t.Error("non-positive ttl must fail")
	}
}

func TestRealRevokeBrokerThenConntrack(t *testing.T) {
	r, fr, fb := newTestReal()
	r.FlushConn = true

	// Warm the neighbor cache so revoke can find the guest's IP.
	fr.output["ip neigh show"] = "10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:11:01 REACHABLE"
	if _, err := r.LookupNeighbor("br-guest", guestIP3); err != nil {
		t.Fatalf("warm lookup: %v", err)
	}

	if err := r.RevokeGuest(guestMAC3); err != nil {
		t.Fatalf("RevokeGuest: %v", err)
	}
	if len(fb.revs) != 1 || fb.revs[0] != guestMAC3.String() {
		t.Fatalf("broker revocations = %v", fb.revs)
	}
	if !fr.ran("conntrack -D -s 10.20.3.44") {
		t.Error("revoke should best-effort flush conntrack for the guest IP")
	}
}

func TestRealRevokeFailsWhenBrokerFails(t *testing.T) {
	r, _, fb := newTestReal()
	fb.err = errors.New("actor overloaded")
	if err := r.RevokeGuest(guestMAC3); err == nil {
		t.Fatal("broker failure must surface")
	}
}

// §4.6 effect ordering: the radio kick happens AFTER the broker revoke
// succeeded, and a failing radio kick must NOT fail the revoke (nft is
// already enforcing; the guest was on an open BSS and simply rejoins).
func TestRealRevokeDeauthAfterBroker(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
	)
	fb := &fakeBroker{auth: map[string]time.Duration{}}
	broker := BrokerFunc{
		AuthorizeFn: fb.Authorize,
		RevokeFn: func(ctx context.Context, mac string) error {
			mu.Lock()
			order = append(order, "broker:"+mac)
			mu.Unlock()
			return fb.Revoke(ctx, mac)
		},
	}
	r := NewReal(broker, "br-guest")
	r.Runner = &fakeRunner{output: map[string]string{}, errFor: map[string]error{}}
	r.Deauth = func(mac string) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "deauth:"+mac)
		return nil
	}

	if err := r.RevokeGuest(guestMAC3); err != nil {
		t.Fatalf("RevokeGuest: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "broker:"+guestMAC3.String() || order[1] != "deauth:"+guestMAC3.String() {
		t.Fatalf("effect order = %v, want broker first then deauth (§4.6)", order)
	}
}

func TestRealRevokeDeauthFailureIgnored(t *testing.T) {
	r, _, fb := newTestReal()
	r.Deauth = func(string) error { return errors.New("hostapd socket unavailable") }

	if err := r.RevokeGuest(guestMAC3); err != nil {
		t.Fatalf("radio-kick failure must not fail the revoke: %v", err)
	}
	if len(fb.revs) != 1 {
		t.Fatalf("broker revocations = %v", fb.revs)
	}
}

func TestRealRevokeNilDeauth(t *testing.T) {
	r, _, _ := newTestReal() // Deauth unset — headless/dev posture
	if err := r.RevokeGuest(guestMAC3); err != nil {
		t.Fatalf("RevokeGuest with nil Deauth: %v", err)
	}
}

func TestRealLookupNeighborParsesLLADDR(t *testing.T) {
	r, fr, _ := newTestReal()
	fr.output["ip neigh show 10.20.3.44 dev br-guest"] =
		"10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:11:01 used 0/0/0 probes 1 REACHABLE"

	mac, err := r.LookupNeighbor("br-guest", guestIP3)
	if err != nil {
		t.Fatalf("LookupNeighbor: %v", err)
	}
	if !bytes.Equal(mac, guestMAC3) {
		t.Fatalf("got %s, want %s", mac, guestMAC3)
	}
	// Second lookup must hit the cache, not the binary.
	before := len(fr.calls)
	if _, err := r.LookupNeighbor("br-guest", guestIP3); err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if len(fr.calls) != before {
		t.Error("cache did not absorb the second lookup")
	}
	// Wrong interface: cache must not leak across bridges (DD-10 scoping).
	fr.output["ip neigh show 10.20.3.44 dev br-lan"] = ""
	if _, err := r.LookupNeighbor("br-lan", guestIP3); err == nil {
		t.Error("cross-interface cache leak — DD-10 violation")
	}
}

func TestRealLookupNeighborFallsBackToDump(t *testing.T) {
	r, fr, _ := newTestReal()
	// Direct show errors out; the dump has the entry.
	fr.errFor["ip neigh show 10.20.3.44 dev br-guest"] = fmt.Errorf("boom")
	fr.output["ip neigh show"] = "" +
		"10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:11:01 REACHABLE\n" +
		"10.20.1.7 dev br-lan lladdr aa:bb:cc:dd:11:02 STALE\n" +
		"fe80::1 dev ppp0 lladdr aa:bb:cc:dd:11:03 REACHABLE\n" +
		"10.20.3.99 dev br-guest  FAILED\n" // no lladdr: skipped

	mac, err := r.LookupNeighbor("br-guest", guestIP3)
	if err != nil {
		t.Fatalf("dump fallback: %v", err)
	}
	if !bytes.Equal(mac, guestMAC3) {
		t.Fatalf("got %s, want %s", mac, guestMAC3)
	}
	// The dump warmed other entries too.
	other, err := r.LookupNeighbor("br-lan", netip.MustParseAddr("10.20.1.7"))
	if err != nil || other.String() != "aa:bb:cc:dd:11:02" {
		t.Fatalf("warm entry = %s, %v", other, err)
	}
	if v6, err := r.LookupNeighbor("ppp0", netip.MustParseAddr("fe80::1")); err != nil || v6 == nil {
		t.Fatalf("v6 entry missing: %v", err)
	}
}

func TestRealBoundPrefersNFTElement(t *testing.T) {
	r, fr, _ := newTestReal()
	fr.output["nft get element inet kcp_zones mac_ip4 { aa:bb:cc:dd:11:01 . 10.20.3.44 }"] =
		"element = { aa:bb:cc:dd:11:01 . 10.20.3.44 }"

	if !r.Bound(guestMAC3, guestIP3) {
		t.Fatal("nft confirms the binding — Bound must be true")
	}
	if !fr.ran("nft get element inet kcp_zones mac_ip4") {
		t.Error("authoritative path is nft get element")
	}

	// Unknown pairing: nft says nothing, neighbor table disagrees → false.
	if r.Bound(guestMAC3, netip.MustParseAddr("10.20.3.99")) {
		t.Fatal("unbound pair must be false (SEC-012)")
	}
}

func TestRealBoundFallsBackToNeighborWitness(t *testing.T) {
	r, fr, _ := newTestReal()
	// nft get element unavailable (no CAP_NET_ADMIN) → error output.
	fr.errFor["nft get element inet kcp_zones mac_ip4 { aa:bb:cc:dd:11:01 . 10.20.3.44 }"] = fmt.Errorf("denied")
	fr.output["ip neigh show"] = "10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:11:01 REACHABLE"

	// Warm the neighbor cache (as Bouncer traffic would) before the
	// fallback witness can be consulted.
	if _, err := r.LookupNeighbor("br-guest", guestIP3); err != nil {
		t.Fatalf("warm lookup: %v", err)
	}

	if !r.Bound(guestMAC3, guestIP3) {
		t.Fatal("neighbor-table witness of the exact pairing should pass the fallback")
	}
	// A different MAC claiming the IP must still fail.
	if r.Bound(mustMAC("aa:bb:cc:dd:11:09"), guestIP3) {
		t.Fatal("spoofed MAC must fail the witness check")
	}
}

func TestRealGuestCountParsesNFTList(t *testing.T) {
	r, fr, _ := newTestReal()
	fr.output["nft list set inet kcp_portal authed_guests"] = `
table inet kcp_portal {
	set authed_guests {
		type ether_addr
		flags timeout
		elements = { aa:bb:cc:dd:11:01 timeout 1h expires 59m59s,
			     aa:bb:cc:dd:11:02 timeout 30m expires 29m59s }
	}
}`
	if got := r.GuestCount(); got != 2 {
		t.Fatalf("GuestCount = %d, want 2", got)
	}

	fr.output["nft list set inet kcp_portal authed_guests"] = `
table inet kcp_portal {
	set authed_guests {
		type ether_addr
		flags timeout
	}
}`
	if got := r.GuestCount(); got != 0 {
		t.Fatalf("empty set: GuestCount = %d, want 0", got)
	}
}

func TestRealContextTimeoutEnforced(t *testing.T) {
	r, _, _ := newTestReal()
	r.Timeout = 10 * time.Millisecond
	slow := &slowRunner{delay: 50 * time.Millisecond}
	r.Runner = slow
	if _, err := r.LookupNeighbor("br-guest", guestIP3); err == nil {
		t.Fatal("slow runner must be cut off by the per-command budget")
	}
}

type slowRunner struct{ delay time.Duration }

func (s *slowRunner) Run(ctx context.Context, _ string, _ ...string) (string, error) {
	select {
	case <-time.After(s.delay):
		return "", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestParseNeighLine(t *testing.T) {
	mac, err := parseNeighLine("10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:11:01 REACHABLE")
	if err != nil || mac.String() != "aa:bb:cc:dd:11:01" {
		t.Fatalf("parse = %s, %v", mac, err)
	}
	if _, err := parseNeighLine("10.20.3.99 dev br-guest FAILED"); err == nil {
		t.Fatal("line without lladdr must error")
	}
}

// Compile-time check: Real satisfies the IF-01 contract like the Mock.
var _ NetCtl = (*Real)(nil)
