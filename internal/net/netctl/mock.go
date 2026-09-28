package netctl

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Mock is an in-memory NetCtl for dev machines and unit tests that have no
// Pi, no nft, and no netlink access. It is NOT wired to a real reconciler
// — AuthorizeGuest/RevokeGuest just mutate a map, and LookupNeighbor/Bound
// answer from tables you seed yourself with the Seed* helpers below.
type Mock struct {
	mu        sync.Mutex
	authed    map[string]time.Time        // MAC string -> expiry
	neighbors map[string]net.HardwareAddr // "iface|ip" -> MAC
	bindings  map[string]string           // MAC string -> IP string
	live      []liveNeighbor              // kernel neighbor-table emulation
}

// NewMock returns a ready-to-use Mock with everything empty.
func NewMock() *Mock {
	return &Mock{
		authed:    make(map[string]time.Time),
		neighbors: make(map[string]net.HardwareAddr),
		bindings:  make(map[string]string),
	}
}

func (m *Mock) AuthorizeGuest(mac net.HardwareAddr, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authed[mac.String()] = time.Now().Add(ttl)
	return nil
}

func (m *Mock) RevokeGuest(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.authed, mac.String())
	return nil
}

func (m *Mock) LookupNeighbor(iface string, ip netip.Addr) (net.HardwareAddr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mac, ok := m.neighbors[iface+"|"+ip.String()]; ok {
		return mac, nil
	}
	return nil, fmt.Errorf("netctl/mock: no neighbor entry for %s on %s (seed one with SeedNeighbor)", ip, iface)
}

func (m *Mock) Bound(mac net.HardwareAddr, ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bindings[mac.String()] == ip.String()
}

func (m *Mock) GuestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	now := time.Now()
	for _, exp := range m.authed {
		if exp.After(now) {
			n++
		}
	}
	return n
}

// --- dev/test seeding helpers below — not part of the NetCtl interface ---

// SeedNeighbor makes LookupNeighbor(iface, ip) resolve to mac, as if the
// kernel neighbor table already learned it.
func (m *Mock) SeedNeighbor(iface string, ip netip.Addr, mac net.HardwareAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.neighbors[iface+"|"+ip.String()] = mac
}

// SeedBinding makes Bound(mac, ip) return true, as if the anti-spoof
// mac_ip4/mac_ip6 set already learned this pairing.
func (m *Mock) SeedBinding(mac net.HardwareAddr, ip netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bindings[mac.String()] = ip.String()
}

// IsAuthorized is a test helper: reports whether mac is currently in
// authed_guests and not yet expired.
func (m *Mock) IsAuthorized(mac net.HardwareAddr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.authed[mac.String()]
	return ok && exp.After(time.Now())
}

// --- neighbor-table emulation (DD-03/DD-10 live view) ---

// liveNeighbor is one kernel neighbor-table entry as the real netlink
// watcher will report it.
type liveNeighbor struct {
	iface string
	ip    netip.Addr
	mac   net.HardwareAddr
	seen  time.Time
}

// SeedNeighborLive adds a live neighbor-table entry (what the kernel
// learned on the wire), as opposed to SeedNeighbor which fakes one
// lookup. The Bouncer's snapshot dump reads these.
func (m *Mock) SeedNeighborLive(iface string, ip netip.Addr, mac net.HardwareAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.live = append(m.live, liveNeighbor{iface: iface, ip: ip, mac: mac, seen: time.Now()})
}

// ListLiveNeighbors returns the live table snapshot, newest first.
func (m *Mock) ListLiveNeighbors() []LiveNeighbor {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LiveNeighbor, 0, len(m.live))
	for _, n := range m.live {
		out = append(out, LiveNeighbor{Interface: n.iface, IP: n.ip, MAC: n.mac.String(), Seen: n.seen})
	}
	return out
}

// LiveNeighbor is the exported snapshot row (matches the neighbors
// package's Entry shape without importing it).
type LiveNeighbor struct {
	Interface string
	IP        netip.Addr
	MAC       string
	Seen      time.Time
}
