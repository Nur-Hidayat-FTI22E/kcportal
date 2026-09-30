package nft

import (
	"fmt"
	"strings"
	"text/template"
	"time"
)

// renderTemplate is parsed once at package init; every Render call
// executes it against a fresh *Plan. Template parse errors are
// programmer errors (bad template text), so panic-at-init is the honest
// handling — the same pattern net/http uses for its patterns.
var renderTemplate = template.Must(template.New("kcp.nft").Funcs(template.FuncMap{
	// kbpsToKBytes converts kbits/s (app.yaml FR-CPT-004) to the kbytes/s
	// unit nft's `limit rate over N kbytes/second` wants: 5000 kbps =
	// 625 kbytes/s (§4.3). Integer division truncates, which only ever
	// makes the cap marginally stricter, never looser.
	"kbpsToBytes": func(kbps int) int { return kbps / 8 },
}).Parse(rulesetTemplate))

// now returns the plan's render clock (Plan.Now, or the real clock when
// unset).
func (p *Plan) now() time.Time {
	if p.Now.IsZero() {
		return time.Now()
	}
	return p.Now
}

// timeoutElem renders one timeout-set element: `timeout T expires R`
// with both rounded up to the next whole second so an entry never
// renders as just-expired between snapshot and `nft -f` (§4.3: "Elemen
// ber-timeout ditulis dengan sisa waktu").
func timeoutElem(expires, now time.Time) string {
	secs := int64(expires.Sub(now).Seconds()) + 1
	return fmt.Sprintf("timeout %ds expires %ds", secs, secs)
}

// --- precomputed element lists (kept in Go so the template stays dumb
// and the formatting is unit-testable) ---

// bind4Elems / bind6Elems return the mac_ip4 / mac_ip6 element bodies,
// skipping already-expired bindings. Concatenation (`mac . ip`) matches
// the set's `ether_addr . ipv4_addr` type.
func (p *Plan) bind4Elems() []string { return p.bindElems(true) }
func (p *Plan) bind6Elems() []string { return p.bindElems(false) }

func (p *Plan) bindElems(v4 bool) []string {
	now := p.now()
	out := make([]string, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		if b.IP.Is4() != v4 || (!b.Expires.IsZero() && !b.Expires.After(now)) {
			continue
		}
		s := fmt.Sprintf("%s . %s", b.MAC, b.IP)
		if !b.Expires.IsZero() {
			s += " " + timeoutElem(b.Expires, now)
		}
		out = append(out, s)
	}
	return out
}

// guestElems returns the authed_guests element bodies, skipping expired.
func (p *Plan) guestElems() []string {
	now := p.now()
	out := make([]string, 0, len(p.Guests))
	for _, g := range p.Guests {
		if !g.Expires.After(now) {
			continue
		}
		out = append(out, g.MAC+" "+timeoutElem(g.Expires, now))
	}
	return out
}

// egressIfs is uplink WAN + tunnels — the egress_if set body (used by
// kcp_filter and kcp_nat; must be non-empty, which Validate enforces).
func (p *Plan) egressIfs() []string {
	return append(append([]string{}, p.Uplinks.WAN...), p.Uplinks.Tunnels...)
}

// dohIPs / dohIPsQuoted are the kcp_portal.doh_block4 element bodies:
// plain for comments/tests, quoted for the set definition.
func (p *Plan) dohIPs() []string {
	return append([]string{}, p.DohShield.BootstrapIPs...)
}

func (p *Plan) dohIPsQuoted() []string {
	ips := p.dohIPs()
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = fmt.Sprintf("%q", ip)
	}
	return out
}

// internetMarks / vpnMarks are the mark literals for zones with
// internet: true / vpn: true.
func (p *Plan) internetMarks() []string {
	out := []string{}
	for _, z := range p.Zones {
		if z.Internet {
			out = append(out, markHex(z.Mark))
		}
	}
	return out
}

func (p *Plan) vpnMarks() []string {
	out := []string{}
	for _, z := range p.Zones {
		if z.VPN {
			out = append(out, markHex(z.Mark))
		}
	}
	return out
}

func markHex(m uint32) string { return fmt.Sprintf("0x%02x", m) }

// macZoneElems renders the mac_zone map elements: `mac : mark` pairs,
// comments documenting which zone each mark belongs to (the map is read
// by the Bouncer; device state lives in state.db).
func (p *Plan) macZoneElems() []string {
	out := make([]string, 0, len(p.MACZones))
	for _, e := range p.MACZones {
		out = append(out, fmt.Sprintf("%s : %s", e.MAC, markHex(e.ZoneMark)))
	}
	return out
}

// appAllowLines renders the DD-14 app_egress exceptions: `ip daddr
// <ip> <proto> dport <port> accept` (no oifname filter — the printer
// sits on the local LAN segment, not behind egress_if).
func (p *Plan) appAllowLines() []string {
	out := make([]string, 0, len(p.AppAllows))
	for _, a := range p.AppAllows {
		out = append(out, fmt.Sprintf("ip daddr %s %s dport %d accept", a.DstIP, a.Proto, a.Port))
	}
	return out
}

// lanAllows flattens every zone's exceptions with its mark resolved —
// the forward chain emits `meta mark <mark> ip daddr <ip> <proto> dport
// <port> accept` per §4.3's POS->printer example.
func (p *Plan) lanAllows() []lanAllowLine {
	out := []lanAllowLine{}
	for _, z := range p.Zones {
		for _, a := range z.LANAllow {
			out = append(out, lanAllowLine{Mark: markHex(z.Mark), Allow: a})
		}
	}
	return out
}

type lanAllowLine struct {
	Mark  string
	Allow LANAllow
}

// renderView carries everything the template needs as EXPORTED fields:
// text/template can only reach exported members, so all list formatting
// happens here in testable Go and the template stays dumb. Empty string
// means "omit the elements clause" (nft rejects `{ }`).
type renderView struct {
	*Plan // exported Plan fields (bridges, portals table fields, SetupMode…) stay reachable from the template

	UplinkElems   string // inline style: "a", "b"
	TunnelElems   string
	Bind4         string // block style: one element per line
	Bind6         string
	Guests        string
	EgressElems   string // never empty — Validate requires an uplink
	InternetMarks string
	VPNMarks      string
	LANAllows     []lanAllowLine
	MACZoneElems  string
	DohIPs        string // quoted inline set elements; empty omits the set
	AppAllowLines []string
}

func joinInline(items []string) string { return strings.Join(items, ", ") }
func joinBlock(items []string) string  { return strings.Join(items, ",\n    ") }

// joinQuoted renders ifname set elements the way the §4.3 reference does:
// ["ppp0", "wg0"] -> `"ppp0", "wg0"`. Marks/MACs/IPs stay unquoted.
func joinQuoted(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

func buildView(p *Plan) *renderView {
	return &renderView{
		Plan:          p,
		UplinkElems:   joinQuoted(p.Uplinks.WAN),
		TunnelElems:   joinQuoted(p.Uplinks.Tunnels),
		Bind4:         joinBlock(p.bind4Elems()),
		Bind6:         joinBlock(p.bind6Elems()),
		Guests:        joinBlock(p.guestElems()),
		EgressElems:   joinQuoted(p.egressIfs()),
		InternetMarks: joinInline(p.internetMarks()),
		VPNMarks:      joinInline(p.vpnMarks()),
		LANAllows:     p.lanAllows(),
		MACZoneElems:  joinBlock(p.macZoneElems()),
		DohIPs:        joinInline(p.dohIPsQuoted()),
		AppAllowLines: p.appAllowLines(),
	}
}

// Render produces the complete kcp.nft text for the plan. It is pure and
// deterministic: identical plans render byte-identical files, which is
// what the 30s drift check (hash comparison) depends on.
func Render(p *Plan) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var sb strings.Builder
	if err := renderTemplate.Execute(&sb, buildView(p)); err != nil {
		return nil, fmt.Errorf("nft: render: %w", err)
	}
	return []byte(sb.String()), nil
}

// rulesetTemplate follows §4.3's reference ruleset: kcp_zones
// (classify), kcp_portal (nat_pre/gate_in/gate_fwd), kcp_filter
// (input/forward/output), kcp_nat (masquerade), kcp_l2 (cable L2
// isolation, DD-07). Table headers use the add/delete pair so one
// `nft -f` transaction atomically replaces each table — never
// `flush ruleset` (DD-04). The bootstrap table is a separate file
// (BootRuleset below), per the reference's "berkas TERPISAH" note.
//
// Sections a plan can leave empty (tunnels, vpn zones, lan_allow rules,
// rate limits) are omitted via {{- if}}, and timeout-set elements are
// precomputed in Go, so the output never contains nft-invalid
// constructs like `{ }` or a dangling comma.
const rulesetTemplate = `# kcp.nft — generated by kotacloud-portal internal/net/nft. DO NOT EDIT.
# Install: nft -c -f (validate), then nft -f (atomic, DD-04 — no flush ruleset).

# ===== 1) identity (§4.2 classification, DD-01/02) =====
add table inet kcp_zones
delete table inet kcp_zones
table inet kcp_zones {
  set uplink_if { type ifname; {{- with .UplinkElems }} elements = { {{ . }} }{{- end }} }
  set tunnel_if { type ifname; {{- with .TunnelElems }} elements = { {{ . }} }{{- end }} }

  map mac_zone  { type ether_addr : mark; {{- with .MACZoneElems }} elements = {
    {{ . }}
  }{{- end }} }   # Bouncer view of state.db devices where state = 'approved'
  map vlan_zone { type ifname : mark; }                           # optional: trunked cable sub-interfaces
  set mac_ip4   { type ether_addr . ipv4_addr; flags timeout; {{- with .Bind4 }} elements = {
    {{ . }}
  }{{- end }} }
  set mac_ip6   { type ether_addr . ipv6_addr; flags timeout; {{- with .Bind6 }} elements = {
    {{ . }}
  }{{- end }} }

  chain classify {
    type filter hook prerouting priority -150; policy accept;
    iifname @uplink_if return
    iifname @tunnel_if return
    meta mark set 0x00
    iifname "{{ .GuestBridge }}" meta mark set 0x03               # DD-01: identity = segment (kept in setup mode so the portal still works)
{{- if .SetupMode }}
    iifname "{{ .MgmtIface }}" meta mark set 0x01                 # setup mode (DD-15): the operator's plane is admin
{{- else }}
    iifname "{{ .LANBridge }}" meta mark set ether saddr map @mac_zone   # no entry -> stays 0x00 (Waiting)
{{- end }}
    meta mark set iifname map @vlan_zone
{{- if .SetupMode }}
    # setup mode (DD-15): mac_ip4/mac_ip6 stay empty (no device-derived
    # identity), so the anti-spoof demotion below MUST be skipped — with an
    # empty set it would demote EVERY guest packet to 0x00 (Waiting) right
    # after DHCP, killing DNS/HTTP/ICMP and the portal with it (observed
    # 2026-10-01: ARP + lease fine, zero post-DHCP reachability).
{{- else }}
    # anti-spoof binding (SEC-012); 0.0.0.0 = DHCP discover, :: / fe80::/10 = DAD/ND
    iifname { "{{ .LANBridge }}", "{{ .GuestBridge }}" } ether type ip  ip saddr != 0.0.0.0 ether saddr . ip saddr != @mac_ip4 meta mark set 0x00
    iifname { "{{ .LANBridge }}", "{{ .GuestBridge }}" } ether type ip6 ip6 saddr != { ::/128, fe80::/10 } ether saddr . ip6 saddr != @mac_ip6 meta mark set 0x00
{{- end }}
  }
}

# ===== 2) pre-auth gate: Waiting & Guest (ERR-01, ERR-04) =====
add table inet kcp_portal
delete table inet kcp_portal
table inet kcp_portal {
  set authed_guests { type ether_addr; flags timeout; {{- with .Guests }} elements = {
    {{ . }}
  }{{- end }} }
  set g_up   { type ipv4_addr; flags dynamic,timeout; timeout 1m; size 1024; }
  set g_down { type ipv4_addr; flags dynamic,timeout; timeout 1m; size 1024; }
{{- if .DohIPs }}
  set doh_block4 { type ipv4_addr; elements = { {{ .DohIPs }} } }   # public-resolver bootstrap IPs (DoHShield)
{{- end }}

  chain nat_pre {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "{{ .LANBridge }}" meta mark 0x00 udp dport 53 dnat ip to {{ .WaitingDNSStub }}   # stub REFUSED (ERR-01)
    iifname "{{ .LANBridge }}" meta mark 0x00 tcp dport 53 dnat ip to {{ .WaitingDNSStub }}
    iifname "{{ .LANBridge }}" meta mark 0x00 tcp dport 80 dnat ip to {{ .WaitingHTTP }}      # Waiting info page
    iifname "{{ .GuestBridge }}" ether saddr != @authed_guests tcp dport 80 dnat ip to {{ .GuestPortal }}   # probe/HTTP -> portal
  }
  chain gate_in {
    type filter hook input priority filter - 10; policy accept;
    iifname != "{{ .GuestBridge }}" return
    ether saddr @authed_guests return
    udp dport { 53, 67 } return                                    # passed on to kcp_filter.input which allows them
    tcp dport { 53, 8080, 8444 } return
    counter drop
  }
  chain gate_fwd {
    type filter hook forward priority filter - 10; policy accept;
{{- if .DohIPs }}
    # DoH/DoT shield (§5 UX): a guest resolving via its own encrypted DNS
    # never fetches the OS captive probe through dnsmasq, so the portal
    # never pops (observed live: Android Private DNS). Applies to authed
    # guests too — the venue's DNS policy is part of the session.
    iifname "{{ .GuestBridge }}" ip daddr @doh_block4 counter drop
{{- end }}
{{- if .DohShield.BlockDoT }}
    iifname "{{ .GuestBridge }}" tcp dport 853 counter drop   # DoT (RFC 7858)
    iifname "{{ .GuestBridge }}" udp dport 853 counter drop   # DoQ (RFC 9250)
{{- end }}
    iifname "{{ .GuestBridge }}" ether saddr != @authed_guests meta l4proto tcp reject with tcp reset   # fail fast, not timeout
    iifname "{{ .GuestBridge }}" ether saddr != @authed_guests reject with icmpx type admin-prohibited
{{- if gt .GuestUpKbps 0 }}
    iifname "{{ .GuestBridge }}" add @g_up   { ip saddr limit rate over {{ kbpsToBytes .GuestUpKbps }} kbytes/second } counter drop
{{- end }}
{{- if gt .GuestDownKbps 0 }}
    oifname "{{ .GuestBridge }}" add @g_down { ip daddr limit rate over {{ kbpsToBytes .GuestDownKbps }} kbytes/second } counter drop
{{- end }}
  }
}

# ===== 3) main filter =====
add table inet kcp_filter
delete table inet kcp_filter
table inet kcp_filter {
  set uplink_if      { type ifname; {{- with .UplinkElems }} elements = { {{ . }} }{{- end }} }
  set tunnel_if      { type ifname; {{- with .TunnelElems }} elements = { {{ . }} }{{- end }} }
  set egress_if      { type ifname; elements = { {{ .EgressElems }} } }
  set internet_zones { type mark; {{- with .InternetMarks }} elements = { {{ . }} }{{- end }} }
  set vpn_required   { type mark; {{- with .VPNMarks }} elements = { {{ . }} }{{- end }} }   # office profile kill-switch (P7)
  set corp_v4        { type ipv4_addr; flags interval; }               # office split-mode CIDRs (P7)
  set g_conn         { type ipv4_addr; flags dynamic; size 1024; }

  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
{{- if .MgmtV4 }}
    # DD-15 anti-lockout: the mgmt subnet rides the uplink iface in the
    # lab (single cable), so it must be accepted BEFORE the WAN jump —
    # input_wan drops everything.
    ip saddr {{ .MgmtV4 }} accept
{{- end }}
    iifname @uplink_if jump input_wan
    iifname @tunnel_if drop
    meta mark 0x00 jump input_waiting
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 20/second accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, echo-request, packet-too-big, time-exceeded, parameter-problem } accept
    udp dport { 53, 67, 547 } accept                               # DNS/DHCP for classified zones
    tcp dport 53 accept
    # per-zone listeners, generated from §2.4:
    meta mark 0x01 tcp dport 443  ct state new limit rate 30/minute accept   # mgmt: Admin only (FR-ZON-005)
    meta mark 0x01 tcp dport 22   ct state new limit rate 30/minute accept   # only when SSH is enabled
    meta mark 0x02 tcp dport { 8443, 8082 } ct state new accept              # apps proxy + onboarding CA (POS)
    iifname "{{ .GuestBridge }}" tcp dport { 8080, 8444 } accept             # portal edge
  }
  chain input_wan {
    icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
    udp dport 546 accept                                           # DHCPv6 client
    drop
  }
  chain input_waiting {                                            # ERR-01
    udp dport { 67, 547 } accept
    udp dport 5354 accept                                          # result of the DNAT :53
    tcp dport { 5354, 8081 } accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
    drop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    meta mark 0x00 drop                                            # Waiting is forwarded nowhere
    oifname @egress_if tcp flags syn tcp option maxseg size set rt mtu   # MSS clamp (PPPoE 1492, WG 1420)
    meta mark 0x03 tcp dport 25 drop                               # FR-CPT-007
    meta mark 0x03 ct state new add @g_conn { ip saddr ct count over 300 } drop
    meta mark @vpn_required oifname @uplink_if drop                # kill-switch full/required (P7)
    ip daddr @corp_v4 oifname @uplink_if drop                      # kill-switch split (P7)
    meta mark @internet_zones oifname @egress_if accept
{{- range .LANAllows }}
    meta mark {{ .Mark }} ip daddr {{ .Allow.DstIP }} {{ .Allow.Proto }} dport {{ .Allow.Port }} accept
{{- end }}
  }

  chain output {
    type filter hook output priority filter; policy accept;
{{- if gt .AppEgressUID 0 }}
    # DD-14: containerized App Pack egress — everything NEW from that
    # uid goes to app_egress and is dropped unless explicitly allowed.
    meta skuid {{ .AppEgressUID }} jump app_egress
{{- end }}
  }
{{- if gt .AppEgressUID 0 }}
  chain app_egress {
    oifname "lo" return                                            # local sockets: proxy->app, resolver stub
    ct state established,related return                            # already-accepted flows keep flowing
{{- range .AppAllowLines }}
    {{ . }}
{{- end }}
    counter drop                                                   # default-deny egress (DD-14)
  }
{{- end }}
}

# ===== 4) NAT =====
add table ip kcp_nat
delete table ip kcp_nat
table ip kcp_nat {
  set egress_if { type ifname; elements = { {{ .EgressElems }} } }
  chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname @egress_if masquerade; }
}
# NAT66 only when ipv6.mode = nat66 (DD-08):
#   table ip6 kcp_nat6 { chain postrouting { type nat hook postrouting priority srcnat; oifname { "ppp0","wan0" } masquerade } }

# ===== 5) cable L2 isolation (DD-07; conditional on TV-03) =====
add table bridge kcp_l2
delete table bridge kcp_l2
table bridge kcp_l2 {
  set known_macs  { type ether_addr; }
  set router_macs { type ether_addr; }
  set l2_pairs    { type ether_addr . ether_addr; }        # same-zone cable pairs allowed direct L2 (max 32, DD-07)
  chain prerouting {
    type filter hook prerouting priority filter; policy accept;
    iifname "eth0" ether saddr != @known_macs ether daddr != @router_macs ether daddr != ff:ff:ff:ff:ff:ff ether type != arp drop
    iifname "eth0" ether saddr @known_macs  ether daddr != @router_macs ether daddr != ff:ff:ff:ff:ff:ff \
        ether daddr & 01:00:00:00:00:00 != 01:00:00:00:00:00 ether saddr . ether daddr != @l2_pairs drop
  }
}
`

// BootRuleset is kcp-boot.nft — a separate file loaded by
// kcp-nft-boot.service before network-pre.target (P-01). It closes the
// plane between boot and the first kcp.nft install; the final
// transaction of kcp.nft (the add/delete pair at the end of a full
// install) removes it again. It is static, so it is a constant rather
// than a rendered template.
const BootRuleset = `# kcp-boot.nft — loaded by kcp-nft-boot.service before network-pre.target (P-01).
# Static on purpose: it must be valid on every boot, before any state is read.
table inet kcp_boot {
  chain input   { type filter hook input priority -200; policy drop; ct state established,related accept; iif "lo" accept; }
  chain forward { type filter hook forward priority -200; policy drop; }
}
`
