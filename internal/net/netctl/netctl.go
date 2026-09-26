// Package netctl defines IF-01: the sole contract through which the guest
// portal (portal-edge) is allowed to affect kernel packet-filtering state.
// portal-edge never touches nft or netlink directly.
package netctl

import (
	"net"
	"net/netip"
	"time"
)

// NetCtl is IF-01 (§7.1).
type NetCtl interface {
	// AuthorizeGuest adds mac to the authed_guests set with the given
	// timeout. Idempotent: calling it again for an already-authorized MAC
	// just refreshes the timeout.
	AuthorizeGuest(mac net.HardwareAddr, ttl time.Duration) error

	// RevokeGuest removes mac from authed_guests, tears down its
	// conntrack entries, and (if currently associated) sends a DEAUTH via
	// hostapd's control socket.
	RevokeGuest(mac net.HardwareAddr) error

	// LookupNeighbor resolves ip to a MAC address via the kernel's
	// neighbor table on iface (DD-10). This — never a MAC the client
	// itself reports — is the only source of truth portal-edge is
	// allowed to trust when identifying who is asking to be authorized.
	LookupNeighbor(iface string, ip netip.Addr) (net.HardwareAddr, error)

	// Bound reports whether mac and ip currently match a learned
	// mac_ip4/mac_ip6 binding (SEC-012 anti-spoof, §4.3).
	Bound(mac net.HardwareAddr, ip netip.Addr) bool

	// GuestCount returns the number of currently-authorized guest MACs.
	GuestCount() int
}
