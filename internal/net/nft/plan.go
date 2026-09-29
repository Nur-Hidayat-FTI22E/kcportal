// Package nft renders the kcp_* nftables tables from desired state and
// applies them the way the design doc §4.3 + DD-04 require: one generated
// kcp.nft file, validated with `nft -c -f`, installed atomically with
// `nft -f` — never `flush ruleset` (which would wipe tables owned by
// other software).
//
// M1 scope: Render() (pure, unit-testable against golden files) and
// Apply() (fail-closed applier). The real data source (state.db → Plan)
// and the wire-in from the state actor arrive with the reconciler work
// later in M1.
package nft

import (
	"fmt"
	"net/netip"
	"time"
)

// Zone is one entry of zones[] (§4.3 chain forward: internet_zones,
// vpn_required, lan_allow).
type Zone struct {
	ID       int
	Name     string
	Mark     uint32 // §2.4: 0x00 waiting, 0x01 admin, 0x02 pos, 0x03 guest
	Internet bool
	VPN      bool // kill-switch "required" (P7)
	LANAllow []LANAllow
}

// LANAllow is one explicit inter-zone exception, rendered as
// `meta mark <mark> ip daddr <ip> <proto> dport <port> accept`.
type LANAllow struct {
	DstIP string
	Proto string // "tcp" | "udp"
	Port  uint16
}

// MACZone is one Bouncer entry of the mac_zone map (§4.2 rule 4: an
// approved device's MAC classifies it into its zone's fwmark).
type MACZone struct {
	MAC      string
	ZoneID   int
	ZoneMark uint32 // resolved from the zone list at render time
}

// Binding is one anti-spoof entry of the timeout sets mac_ip4/mac_ip6
// (SEC-012, DD-03 lease/neighbor watcher). Expiry renders as
// `timeout <total> expires <remaining>` exactly as §4.3 states.
type Binding struct {
	MAC     string
	IP      netip.Addr
	Expires time.Time
}

// Guest is one authorized guest MAC in kcp_portal.authed_guests; the
// set carries timeouts, so expiry renders the same way as bindings.
type Guest struct {
	MAC     string
	Expires time.Time
}

// Uplinks is the interface naming the generator needs to distinguish
// where the internet is (masquerade, MSS clamp, WAN input policy).
type Uplinks struct {
	WAN     []string // e.g. {"wan0"} or {"ppp0"} — pppoe mode drops wan0
	Tunnels []string // e.g. {"wg0"} — empty when no VPN is configured
}

// DoHShield carries the mitigations against clients whose encrypted DNS
// bypasses the captive DNS (Android Private DNS, Chrome DoH, DoT, DoQ).
// Without it such a client never resolves the OS captive-probe hostname
// through dnsmasq, never receives the 302, and the phone marks the
// network "no internet" instead of popping the portal (observed live,
// 2026-09: guest phone on Chrome/cloudflare-dns DoH). Rendered as drops
// at the TOP of kcp_portal.gate_fwd — before any authed_guests
// exception, because the venue's DNS policy applies to the whole guest
// session, not just the pre-auth window. The router's own upstream
// resolver queries are unaffected: they originate locally, not iifname
// br-guest.
//
// Encrypted DNS cannot be blocked per port (DoH hides inside 443), so
// the shield works on the BOOTSTRAP level: the well-known anycast IPs
// of the dominant public resolvers are blocked outright, which makes
// Private DNS bootstrap fail and the OS fall back to the DHCP-provided
// resolver (dnsmasq) — exactly the path the portal owns.
type DoHShield struct {
	// BootstrapIPs are blocked for ALL guest traffic (any port — DoH
	// rides 443, plain DNS rides 53; blocking the IPs covers both).
	BootstrapIPs []string
	// BlockDoT drops tcp/udp :853 (DoT + DoQ) from guests.
	BlockDoT bool
}

// DefaultDohBootstrapIPs are the anycast bootstrap endpoints of the
// public resolvers that ship in Android's Private DNS picker and the
// Chrome/Firefox DoH allowlists. IPv4 only for now: the Café profile
// does not announce IPv6 on the bridges (no RA), so there is no v6 path
// to shield yet — revisit with DD-08 (native /64 per segment).
func DefaultDohBootstrapIPs() []string {
	return []string{
		"1.1.1.1", "1.0.0.1", // Cloudflare (+ WARP bootstrap)
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", "149.112.112.112", // Quad9
		"208.67.222.222", "208.67.220.220", // OpenDNS
		"94.140.14.14", "94.140.15.15", // AdGuard
	}
}

// Plan is the complete desired state rendered into kcp.nft.
type Plan struct {
	SetupMode bool // DD-15: br-lan gets mark 0x01 instead of mac_zone lookup
	// SetupMgmtIface names the setup-mode management plane that classify
	// stamps 0x01 (DD-15 spirit: the operator's own plane stays admin).
	// Empty falls back to LANBridge — see MgmtIface.
	SetupMgmtIface string

	// MgmtIface resolves the classify view's management plane: the
	// explicit SetupMgmtIface when set, otherwise LANBridge.
	MgmtIface string

	// MgmtV4 is the management subnet (CIDR) accepted at the top of the
	// input chain, BEFORE the uplink jump. Needed when the mgmt plane
	// shares the uplink interface (single-cable lab: KCP_WAN_IFACE=eth0
	// AND SSH over eth0) — without it, input_wan's drop eats the
	// operator's own SSH (observed E2E 2026-09-28). Empty = no rule.
	MgmtV4 string

	Uplinks Uplinks

	Zones []Zone

	// GuestBridge is the bridge whose clients are captive (DD-01: br-guest).
	GuestBridge string
	// LANBridge is the staff/management bridge (DD-01: br-lan).
	LANBridge string

	// GuestPortal is ip:port the unauthenticated guest HTTP is DNAT'd to
	// (portal-edge listener, §2.4: 10.20.3.1:8080).
	GuestPortal string
	// WaitingDNSStub / WaitingHTTP are the Waiting-zone info page
	// endpoints (ERR-01: 10.20.99.1:5354 DNS REFUSED stub, :8081 page).
	WaitingDNSStub string
	WaitingHTTP    string

	// GuestUpKbps / GuestDownKbps are per-client rate limits (FR-CPT-004,
	// portal.uplink_kbps/downlink_kbps in app.yaml). 0 = no limit.
	GuestUpKbps   int
	GuestDownKbps int

	// DohShield renders the encrypted-DNS bypass drops in gate_fwd (see
	// the type's comment). Zero value renders nothing — the reconciler
	// wires the defaults.
	DohShield DoHShield

	// AppEgressUID is the host uid the App Pack containers run as
	// (kcapps). >0 wires the DD-14 chain: every NEW outbound connection
	// from that uid is dropped by kcp_filter app_egress unless an
	// explicit AppAllow matches. Loopback and established flows always
	// pass. 0 (or negative) renders nothing — egress stays open (dev
	// boxes, explicit opt-out).
	AppEgressUID int
	// AppAllows are the explicit egress exceptions (e.g. the LAN
	// receipt printer 10.20.2.20:9100, IF-03). Rendered as
	// `ip daddr <ip> <proto> dport <port> accept` inside app_egress.
	AppAllows []LANAllow

	Bindings []Binding // mac_ip4/mac_ip6 sets
	Guests   []Guest   // authed_guests set

	// MACZones fills the mac_zone map (approved devices, Bouncer view of
	// state.db devices where state = 'approved'). Empty in setup mode.
	MACZones []MACZone

	// Now is the clock used for expiry math when rendering timeout
	// elements (`timeout Ns expires Ns`) and for dropping expired rows.
	// Zero means real time.Now(); the reconciler sets it from the
	// handler's clock so one clock drives the whole pipeline and Render
	// stays a pure, deterministic function of the plan.
	Now time.Time
}

// Validate rejects plans that would render a broken or unsafe ruleset —
// the generator's last line of defence before Apply's nft -c check.
func (p *Plan) Validate() error {
	if p.GuestBridge == "" || p.LANBridge == "" {
		return fmt.Errorf("nft: GuestBridge and LANBridge are required")
	}
	p.MgmtIface = p.LANBridge
	if p.SetupMode && p.SetupMgmtIface != "" {
		p.MgmtIface = p.SetupMgmtIface
	}
	if p.GuestBridge == p.LANBridge {
		return fmt.Errorf("nft: GuestBridge and LANBridge must differ (DD-01 fixed pairing)")
	}
	if len(p.Uplinks.WAN) == 0 && len(p.Uplinks.Tunnels) == 0 {
		return fmt.Errorf("nft: at least one uplink interface is required (egress would be unreachable)")
	}
	marks := map[uint32]bool{}
	zoneMarks := map[int]uint32{}
	for _, z := range p.Zones {
		if marks[z.Mark] {
			return fmt.Errorf("nft: duplicate zone mark 0x%02x", z.Mark)
		}
		marks[z.Mark] = true
		zoneMarks[z.ID] = z.Mark
		for _, a := range z.LANAllow {
			if a.Proto != "tcp" && a.Proto != "udp" {
				return fmt.Errorf("nft: zone %q lan_allow proto %q must be tcp or udp", z.Name, a.Proto)
			}
			if _, err := netip.ParseAddr(a.DstIP); err != nil {
				return fmt.Errorf("nft: zone %q lan_allow dst_ip %q is not an IP: %v", z.Name, a.DstIP, err)
			}
			if a.Port == 0 {
				return fmt.Errorf("nft: zone %q lan_allow port 0 is invalid", z.Name)
			}
		}
	}
	for _, a := range p.AppAllows {
		if a.Proto != "tcp" && a.Proto != "udp" {
			return fmt.Errorf("nft: app_egress allow proto %q must be tcp or udp", a.Proto)
		}
		if _, err := netip.ParseAddr(a.DstIP); err != nil {
			return fmt.Errorf("nft: app_egress allow dst_ip %q is not an IP: %v", a.DstIP, err)
		}
		if a.Port == 0 {
			return fmt.Errorf("nft: app_egress allow port 0 is invalid")
		}
	}
	seenMAC := map[string]bool{}
	for i := range p.MACZones {
		m := &p.MACZones[i]
		if seenMAC[m.MAC] {
			return fmt.Errorf("nft: duplicate mac_zone entry for %s", m.MAC)
		}
		seenMAC[m.MAC] = true
		mark, ok := zoneMarks[m.ZoneID]
		if !ok {
			return fmt.Errorf("nft: mac_zone entry %s references unknown zone id %d", m.MAC, m.ZoneID)
		}
		m.ZoneMark = mark
	}
	return nil
}
