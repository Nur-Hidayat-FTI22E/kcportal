package netctl

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"kotacloud-portal/internal/net/netlink"
)

// CommandRunner executes a helper binary and returns combined output —
// the seam that lets tests substitute fake `ip`/`nft` binaries.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner shells out to the real tools.
type ExecRunner struct{}

// Run implements CommandRunner with os/exec.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// AuthBroker is the single-writer path for authed_guests (§7.3: "portal
// | via NetCtl -> state actor | nft"). The real implementation is a
// closure over Actor.Do with the required deadline context (IF-02);
// tests pass a stub.
type AuthBroker interface {
	Authorize(ctx context.Context, mac string, ttl time.Duration) error
	Revoke(ctx context.Context, mac string) error
}

// BrokerFunc adapts functions to AuthBroker.
type BrokerFunc struct {
	AuthorizeFn func(ctx context.Context, mac string, ttl time.Duration) error
	RevokeFn    func(ctx context.Context, mac string) error
}

// Authorize implements AuthBroker.
func (b BrokerFunc) Authorize(ctx context.Context, mac string, ttl time.Duration) error {
	return b.AuthorizeFn(ctx, mac, ttl)
}

// Revoke implements AuthBroker.
func (b BrokerFunc) Revoke(ctx context.Context, mac string) error { return b.RevokeFn(ctx, mac) }

// DeauthFunc kicks a station off the Wi-Fi AP (§4.6 effect ordering:
// nft revoke first, then the radio). cmd/kcportald fills it with the
// hostapdctl DEAUTHENTICATE path; nil = radio kick unavailable, and the
// nft/conntrack enforcement stands alone (headless/dev environments).
type DeauthFunc func(mac string) error

// Real is the production NetCtl (IF-01). Kernel reads go straight to
// rtnetlink (internal/net/netlink — DD-03, no `ip` subprocess) with the
// iproute2 ExecRunner kept as a fallback for environments where the
// netlink socket is unavailable; guest authorization is brokered through
// the state actor so authed_guests never has two writers. Hostapd DEAUTH
// rides DeauthFunc (MOD-WIFI, wired in cmd/kcportald).
type Real struct {
	Runner    CommandRunner
	Broker    AuthBroker
	GuestIf   string        // bridge whose clients are guests (br-guest)
	CacheTTL  time.Duration // neighbor cache freshness bound
	Timeout   time.Duration // per-command budget (FR-BNC-001's ≤2s detection shape)
	FlushConn bool          // best-effort `conntrack -D` on revoke (needs the tool; skip silently otherwise)

	// NetlinkDumper replaces the `ip neigh` dump when set (production:
	// rtnetlink RTM_GETNEIGH via internal/net/netlink). When nil or when
	// the dump errors, Real falls back to ExecRunner(`ip neigh show`).
	NetlinkDumper func() ([]netlink.Neigh, error)

	// Deauth kicks the MAC off the guest AP after the kernel-side revoke
	// has taken effect (§4.6: nft first, radio second). Best-effort by
	// design: a radio hiccup must not fail a revoke that nft already
	// enforced — the client was on an OPEN BSS, it simply rejoins.
	Deauth DeauthFunc

	mu     sync.Mutex
	neigh  map[netip.Addr]neighEntry // live neighbor cache from the last dump
	dumped time.Time
}

type neighEntry struct {
	mac   net.HardwareAddr
	iface string
	seen  time.Time
}

// NewReal wires a Real NetCtl with sane Pi budgets.
func NewReal(broker AuthBroker, guestIf string) *Real {
	return &Real{
		Runner:   ExecRunner{},
		Broker:   broker,
		GuestIf:  guestIf,
		CacheTTL: 5 * time.Second,
		Timeout:  2 * time.Second,
	}
}

// AuthorizeGuest implements IF-01: idempotent add (or timeout refresh)
// of the MAC in authed_guests, via the state actor.
func (r *Real) AuthorizeGuest(mac net.HardwareAddr, ttl time.Duration) error {
	if mac == nil || len(mac) == 0 {
		return fmt.Errorf("netctl/real: AuthorizeGuest: empty MAC")
	}
	if ttl <= 0 {
		return fmt.Errorf("netctl/real: AuthorizeGuest: ttl must be positive")
	}
	ctx, cancel := r.ctx()
	defer cancel()
	return r.Broker.Authorize(ctx, mac.String(), ttl)
}

// RevokeGuest implements IF-01: remove from authed_guests (state actor),
// then best-effort conntrack teardown so an authorized session dies
// immediately instead of riding established state.
func (r *Real) RevokeGuest(mac net.HardwareAddr) error {
	if mac == nil || len(mac) == 0 {
		return fmt.Errorf("netctl/real: RevokeGuest: empty MAC")
	}
	ctx, cancel := r.ctx()
	defer cancel()
	if err := r.Broker.Revoke(ctx, mac.String()); err != nil {
		return err
	}
	// Best-effort: find the guest's current IP from the neighbor cache
	// and flush its conntrack entries. Failure here does not fail the
	// revoke — nft gate_fwd already rejects unauthorized MACs.
	if ip, ok := r.ipForMACCached(mac.String()); ok && r.FlushConn {
		_, _ = r.Runner.Run(ctx, "conntrack", "-D", "-s", ip)
	}
	// Best-effort radio kick (§4.6 second step). DeauthFunc's contract is
	// "log your own errors": Real cannot — the nft side is already live.
	if r.Deauth != nil {
		_ = r.Deauth(mac.String())
	}
	return nil
}

// LookupNeighbor implements IF-01/DD-10: resolve ip → MAC from the
// kernel neighbor table (`ip neigh show <ip> dev <iface>`), with a short
// TTL cache to keep the ≤2s detection budget cheap under load.
func (r *Real) LookupNeighbor(iface string, ip netip.Addr) (net.HardwareAddr, error) {
	if !ip.IsValid() {
		return nil, fmt.Errorf("netctl/real: LookupNeighbor: invalid ip")
	}
	if e, ok := r.cached(iface, ip); ok {
		return e, nil
	}
	ctx, cancel := r.ctx()
	defer cancel()
	out, err := r.Runner.Run(ctx, "ip", "neigh", "show", ip.String(), "dev", iface)
	if err != nil || strings.TrimSpace(out) == "" {
		// Fall back to a full dump (some iproute2 versions omit dev in
		// show output; the dump also warms the cache for other lookups).
		if derr := r.dumpNeigh(ctx); derr != nil {
			return nil, fmt.Errorf("netctl/real: neighbor lookup %s@%s: %v (dump: %v)", ip, iface, err, derr)
		}
		if e, ok := r.cached(iface, ip); ok {
			return e, nil
		}
		return nil, fmt.Errorf("netctl/real: no neighbor entry for %s on %s (DD-10: identity comes only from the kernel table)", ip, iface)
	}
	mac, err := parseNeighLine(out)
	if err != nil {
		return nil, fmt.Errorf("netctl/real: neighbor %s@%s: %w", ip, iface, err)
	}
	r.remember(iface, ip, mac)
	return mac, nil
}

// parseNeighLine extracts the LLADDR from `ip neigh` output:
// "10.20.3.44 dev br-guest lladdr aa:bb:cc:dd:ee:ff REACHABLE".
func parseNeighLine(line string) (net.HardwareAddr, error) {
	for _, f := range strings.Fields(line) {
		if strings.Contains(f, ":") && len(f) == 17 { // "aa:bb:cc:dd:ee:ff"
			mac, err := net.ParseMAC(f)
			if err != nil {
				return nil, err
			}
			return mac, nil
		}
	}
	return nil, fmt.Errorf("no lladdr in %q", strings.TrimSpace(line))
}

// Bound implements IF-01/SEC-012: does the kernel-owned ruleset agree
// that this MAC owns this IP? Authoritative answer comes from nft:
//
//	nft get element inet kcp_zones mac_ip4 { <mac> . <ip> }
//
// `get element` needs CAP_NET_ADMIN; when it fails we fall back to the
// neighbor-table cross-check (MAC↔IP observed on the wire), which is
// still client-untrusted input, just a weaker witness — logged by the
// caller via event bouncer.spoof_suspect on mismatch.
func (r *Real) Bound(mac net.HardwareAddr, ip netip.Addr) bool {
	if mac == nil || !ip.IsValid() {
		return false
	}
	ctx, cancel := r.ctx()
	defer cancel()
	set := "mac_ip4"
	if ip.Is6() {
		set = "mac_ip6"
	}
	elem := fmt.Sprintf("{ %s . %s }", mac, ip)
	out, err := r.Runner.Run(ctx, "nft", "get", "element", "inet", "kcp_zones", set, elem)
	if err == nil && strings.Contains(out, mac.String()) {
		return true
	}
	// Fallback witness: the kernel must have learned this exact pairing.
	if n, ok := r.lookupAny(ip); ok && strings.EqualFold(n.String(), mac.String()) {
		return true
	}
	return false
}

// GuestCount implements IF-01: count live authed_guests elements.
// Plain-text line parse of `nft list set`: element lines carry
// `timeout Xs expires Ys`, while the set header line declares
// `flags timeout` — lines are classified so the header never skews the
// count (portable across busybox environments; JSON parsing is the M3
// hardening pass).
func (r *Real) GuestCount() int {
	ctx, cancel := r.ctx()
	defer cancel()
	out, err := r.Runner.Run(ctx, "nft", "list", "set", "inet", "kcp_portal", "authed_guests")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.Contains(t, "flags timeout") {
			continue // set declaration, not an element
		}
		if strings.Contains(t, "timeout ") {
			n++
		}
	}
	return n
}

// --- internals ---

func (r *Real) ctx() (context.Context, context.CancelFunc) {
	t := r.Timeout
	if t <= 0 {
		t = 2 * time.Second
	}
	return context.WithTimeout(context.Background(), t)
}

func (r *Real) remember(iface string, ip netip.Addr, mac net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.neigh == nil {
		r.neigh = make(map[netip.Addr]neighEntry)
	}
	r.neigh[ip] = neighEntry{mac: mac, iface: iface, seen: time.Now()}
}

func (r *Real) cached(iface string, ip netip.Addr) (net.HardwareAddr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.neigh[ip]
	if !ok || time.Since(e.seen) > r.cacheTTL() || (iface != "" && e.iface != iface) {
		return nil, false
	}
	return e.mac, true
}

func (r *Real) cacheTTL() time.Duration {
	if r.CacheTTL <= 0 {
		return 5 * time.Second
	}
	return r.CacheTTL
}

// dumpNeigh refreshes the internal cache. Preferred path: one rtnetlink
// RTM_GETNEIGH dump (internal/net/netlink — same bytes the kernel hands
// iproute2, minus a fork+exec per poll). Fallback: `ip neigh show` via
// the CommandRunner seam, for environments where the netlink socket is
// unavailable.
func (r *Real) dumpNeigh(ctx context.Context) error {
	var nlErr error
	if r.NetlinkDumper != nil {
		rows, err := r.NetlinkDumper()
		if err == nil {
			r.storeNeigh(rows)
			return nil
		}
		nlErr = err // remember; fall through to the iproute2 fallback
	}
	out, err := r.Runner.Run(ctx, "ip", "neigh", "show")
	if err != nil {
		if nlErr != nil {
			return fmt.Errorf("netlink dump: %v; ip fallback: %w", nlErr, err)
		}
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.neigh == nil {
		r.neigh = make(map[netip.Addr]neighEntry)
	}
	now := time.Now()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		var mac net.HardwareAddr
		var iface string
		for i, tok := range f {
			if tok == "dev" && i+1 < len(f) {
				iface = f[i+1]
			}
			if len(tok) == 17 && strings.Contains(tok, ":") {
				mac, _ = net.ParseMAC(tok)
			}
		}
		if mac != nil {
			r.neigh[ip] = neighEntry{mac: mac, iface: iface, seen: now}
		}
	}
	r.dumped = now
	return nil
}

// storeNeigh merges a netlink dump into the cache.
func (r *Real) storeNeigh(rows []netlink.Neigh) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.neigh == nil {
		r.neigh = make(map[netip.Addr]neighEntry)
	}
	now := time.Now()
	for _, n := range rows {
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue // netlink.Client already filtered failed states
		}
		r.neigh[n.IP] = neighEntry{mac: mac, iface: n.Iface, seen: now}
	}
	r.dumped = now
}

// lookupAny finds a MAC for ip regardless of interface.
func (r *Real) lookupAny(ip netip.Addr) (net.HardwareAddr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.neigh[ip]
	return e.mac, ok
}

// ipForMACCached is the reverse of the cache, used by conntrack teardown.
func (r *Real) ipForMACCached(mac string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, e := range r.neigh {
		if strings.EqualFold(e.mac.String(), mac) {
			return ip.String(), true
		}
	}
	return "", false
}

// ListLiveNeighbors dumps the internal cache — the neighbors watcher's
// Provider seam, mirroring the Mock's contract so wiring is identical
// in both modes.
func (r *Real) ListLiveNeighbors() []LiveNeighbor {
	ctx, cancel := r.ctx()
	defer cancel()
	_ = r.dumpNeigh(ctx) // best-effort refresh; stale entries are still useful
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]LiveNeighbor, 0, len(r.neigh))
	for ip, e := range r.neigh {
		out = append(out, LiveNeighbor{Interface: e.iface, IP: ip, MAC: e.mac.String(), Seen: e.seen})
	}
	return out
}
