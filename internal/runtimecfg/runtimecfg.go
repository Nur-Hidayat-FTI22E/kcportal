// Package runtimecfg renders the hostapd.conf and dnsmasq.conf (plus the
// per-device DHCP reservation files, §4.5) from state.db — the same
// source-of-truth discipline as the nftables pipeline (§4.3): desired
// state lives in state.db, the generator output is deterministic and
// only rewritten when it actually changed, and runtime interface
// surgery (bridges, addresses, VLANs) is deliberately NOT this daemon's
// job. The ops-side `deploy/pi/kcp-net-apply.sh` owns the kernel-facing
// half; kcportald owns the files and restarts the daemons whose config
// it owns: dnsmasq-kcp on pool-level conf changes (hosts.d rides
// inotify per-file, no restart), hostapd@kcportald on radio-affecting
// changes. The restart privilege is pinned by the polkit rule
// deploy/pi/10-kcportal-restart.rules (two units, verb restart only).
//
// Why detection instead of netlink wiring: changing the interface plan
// is the one step able to cut the operator's own management access
// (SSH rides eth0 until the production ruleset is installed). Keeping
// it manual-and-reviewed (DD-15 spirit) removes the lockout foot-gun;
// the loader simply refuses to start serving Wi-Fi/DHCP config until
// the bridges exist and carry the expected addresses (fail-closed,
// NFR-REL-04, same as the nft applier).
package runtimecfg

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"kotacloud-portal/internal/net/dhcp"
	"kotacloud-portal/internal/net/wifi"
	"kotacloud-portal/internal/store"
)

// Paths bundles the on-disk locations the renderer writes to.
type Paths struct {
	RunDir     string // /run/kcportal (tmpfs, PD-4)
	HostapdDir string // /run/hostapd — config lives in RAM; the unit file regenerates it
	DnsmasqDir string // /run/kcportal/dnsmasq
}

// LoadOpts selects what the renderer is allowed to produce.
type LoadOpts struct {
	StaffPSK    string           // WPA2 passphrase (secrets, §7.3); empty = skip hostapd render
	UpstreamDNS []string         // dnsmasq no-resolv servers
	TagByZone   map[int]string   // zone id -> dnsmasq tag (e.g. 1 -> z1)
	DeviceLease string           // static lease time for approved devices ("12h")
	Now         func() time.Time // injectable clock
	Log         *slog.Logger
}

// DetectIFace finds an interface by prefix, preferring exact order:
// candidates are tried in the given order, first hit wins ("wlan0" wins
// over "wlan0_1" for the radio because exact names come first).
func DetectIFace(prefixes ...string) (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	names := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		names = append(names, ifc.Name)
	}
	sort.Strings(names) // deterministic: wlan0 before wlan0_1
	for _, p := range prefixes {
		for _, n := range names {
			if strings.HasPrefix(n, p) {
				return n, true
			}
		}
	}
	return "", false
}

// DetectBridges reports which of the named bridges exist.
func DetectBridges(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		for _, n := range names {
			if ifc.Name == n {
				out[n] = true
			}
		}
	}
	return out
}

// DetectAddr returns the first IPv4 address of an interface.
func DetectAddr(iface string) (string, bool) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return "", false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return "", false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP.String(), true
		}
	}
	return "", false
}

// RequireBridges fails closed (NFR-REL-04) unless both bridges exist.
// The config for hostapd (bridge=...) and dnsmasq (interface=...) is
// useless — and for hostapd actively harmful — when the bridge is
// missing, so refuse to render rather than guess.
func RequireBridges(log *slog.Logger) error {
	have := DetectBridges("br-lan", "br-guest")
	var missing []string
	for _, b := range []string{"br-lan", "br-guest"} {
		if !have[b] {
			missing = append(missing, b)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("runtimecfg: bridge(s) %s missing — run deploy/pi/kcp-net-apply.sh first (fail-closed: no usable Wi-Fi/DHCP config without the §2.4 interface plan)",
			strings.Join(missing, ", "))
	}
	log.Info("bridges present", "br-lan", true, "br-guest", true)
	return nil
}

// RenderHostapd builds the two-BSS config (DD-01) from the detected
// radio (default: wlan0 + wlan0_1 per §4.4), honoring configured SSIDs.
// The staff PSK is injected at render time only (§7.3) and the file is
// written 0600 into tmpfs (PD-4).
func RenderHostapd(staffSSID, guestSSID, staffPSK string) ([]byte, error) {
	radio, ok := DetectIFace("wlan0")
	if !ok {
		return nil, fmt.Errorf("runtimecfg: no wifi radio (wlan0*) found — is the Pi 5 radio enabled? (rfkill unblock wifi)")
	}
	guest := radio + "_1" // hostapd creates the BSS1 virtual iface itself
	if g, ok := DetectIFace("wlan0_"); ok {
		guest = g
	}
	venue := "portal" // fallback when no configured SSID arrives
	if staffSSID != "" {
		venue = strings.TrimSuffix(staffSSID, "-Staff")
	}
	cfg := wifi.Default(venue, staffPSK)
	// The Pi 5 radio (CYW43455) rejects 80 MHz AP mode ("no second
	// channel offset"): run 802.11n 20 MHz on 5 GHz until the renderer
	// grows an iw-driven capability probe (M3+).
	cfg.Radio.VHT80 = false
	// Inside kcportald's RuntimeDirectory — the hostapd unit's
	// ReadWritePaths can then rely on a path that always exists.
	cfg.CtrlDir = "/run/kcportal/hostapd"
	cfg.BSS[0].Iface = radio
	cfg.BSS[1].Iface = guest
	if staffSSID != "" {
		cfg.BSS[0].SSID = staffSSID
	}
	if guestSSID != "" {
		cfg.BSS[1].SSID = guestSSID
	}
	return wifi.Render(cfg)
}

// RenderHostapdSingleBSS is the documented fallback for radios whose
// firmware cannot run two concurrent AP interfaces. The Pi 5's onboard
// CYW43455 is one: `iw list` reports #{ AP } <= 1 in every "valid
// interface combination", so DD-01's dual BSS (wlan0 + wlan0_1) fails
// with EBUSY at "Failed to create interface wlan0_1". The surviving BSS
// is the GUEST portal one — it is the SSID clients join to be
// onboarded (the whole ERR-01 flow); staff connectivity still exists
// through the br-lan side. Select it with KCP_WIFI_BSS=single.
// Upgrade path (M4+): a second radio (USB AP dongle) restores DD-01.
func RenderHostapdSingleBSS(guestSSID string) ([]byte, error) {
	radio, ok := DetectIFace("wlan0")
	if !ok {
		return nil, fmt.Errorf("runtimecfg: no wifi radio (wlan0*) found")
	}
	ssid := guestSSID
	if ssid == "" {
		ssid = "portal" // DD-01's guest SSID
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Single-BSS fallback (CYW43455: #{ AP } <= 1) — guest portal BSS only.")
	w("# DD-01 dual BSS returns when a second radio is added (M4+).")
	w("ctrl_interface=/run/kcportal/hostapd")
	w("ctrl_interface_group=kcportal")
	w("country_code=ID")
	w("ieee80211d=1")
	w("interface=%s", radio)
	w("driver=nl80211")
	w("hw_mode=a")
	w("channel=36")
	w("ieee80211n=1") // 20 MHz: the firmware rejects 80 MHz AP (VHT) mode
	w("wmm_enabled=1")
	w("max_num_sta=16")
	w("ap_max_inactivity=300")
	w("disassoc_low_ack=1")
	w("ssid=%s", ssid)
	w("bridge=br-guest")
	w("ap_isolate=1")
	w("wpa=0") // open (FR-WIF-010): portal owns the auth path
	return []byte(b.String()), nil
}

// RenderDnsmasq builds dnsmasq.conf + the reservation file set from
// state.db (§4.5): the Waiting pool stays dynamic (120 s, TV-02), every
// approved device gets a static lease in hosts.d keyed by MAC
// (lowercase canonical), guests keep the 2 h pool on br-guest.
func RenderDnsmasq(db *sql.DB, upDNS []string, tagByZone map[int]string, devLease string) ([]byte, []dhcp.Reservation, error) {
	now := time.Now()
	snap, err := store.LoadPlan(db, now)
	if err != nil {
		return nil, nil, fmt.Errorf("runtimecfg: load plan: %w", err)
	}

	pools := []dhcp.ZonePool{
		// FR-NET-003: Waiting is the only dynamic pool, on br-lan.
		{Tag: "waiting", Bridge: "br-lan", RangeStart: "10.20.99.10", RangeEnd: "10.20.99.250", Subnet: "255.255.255.0", Lease: "120s", Router: "10.20.99.1", DNS: "10.20.99.1"},
		{Tag: "guest", Bridge: "br-guest", RangeStart: "10.20.3.20", RangeEnd: "10.20.3.250", Subnet: "255.255.255.0", Lease: "2h", Router: "10.20.3.1", DNS: "10.20.3.1"},
	}
	// Static pools for approved zones (TV-02) come from the zones table.
	for _, z := range snap.Zones {
		tag, ok := tagByZone[z.ID]
		if !ok || tag == "" {
			continue // waiting (virtual) and unknown zones have no pool
		}
		if z.Subnet == "" {
			continue
		}
		router := zoneGateway(z.Subnet)
		if router == "" {
			continue
		}
		// dnsmasq's dhcp-range wants a BARE network address + netmask — a
		// CIDR start is rejected by the parser ("only one tag allowed" on
		// dnsmasq 2.90). Convert "10.20.2.0/24" -> ("10.20.2.0", mask).
		net, ipnet, err := net.ParseCIDR(z.Subnet)
		if err != nil || ipnet == nil {
			continue
		}
		pools = append(pools, dhcp.ZonePool{
			Tag: tag, Bridge: "br-lan", RangeStart: net.String(),
			Subnet: netMask(ipnet), Lease: "12h", Router: router, DNS: router,
		})
	}
	sort.Slice(pools, func(i, j int) bool { // deterministic render
		if pools[i].Tag == pools[j].Tag {
			return pools[i].Bridge < pools[j].Bridge
		}
		return pools[i].Tag < pools[j].Tag
	})

	// Reservations: approved devices with a lease IP (DD-03 IPAM).
	ipByMAC := make(map[string]string, len(snap.Bindings))
	for _, l := range snap.Bindings {
		if l.IP.IsValid() && !l.IP.Is4In6() {
			ipByMAC[l.MAC] = l.IP.String()
		}
	}
	resv := make([]dhcp.Reservation, 0, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.State != "approved" || d.ZoneID <= 0 {
			continue
		}
		tag, ok := tagByZone[d.ZoneID]
		if !ok || tag == "" {
			continue
		}
		ip, ok := ipByMAC[d.MAC]
		if !ok {
			continue // lease not granted yet; the next pass renders it
		}
		resv = append(resv, dhcp.Reservation{MAC: d.MAC, ZoneTag: tag, IP: ip, LeaseTime: devLease})
	}
	sort.Slice(resv, func(i, j int) bool { return resv[i].MAC < resv[j].MAC })

	cfg := &dhcp.Config{
		UpstreamDNS: upDNS,
		LocalDomain: "kcp.internal",
		Addresses: map[string]string{
			"admin":   "10.20.1.1",
			"pos":     "10.20.2.1",
			"portal":  "10.20.3.1",
			"waiting": "10.20.99.1",
		},
		Pools: pools,
	}
	out, err := dhcp.Render(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("runtimecfg: render dnsmasq: %w", err)
	}
	return out, resv, nil
}

// netMask renders an IPNet's mask in dotted-decimal (255.255.255.0).
func netMask(ipnet *net.IPNet) string {
	if m := ipnet.Mask; len(m) == 4 {
		return net.IP(m).String()
	}
	return "255.255.255.0"
}

// zoneGateway derives the router address of a CIDR (first usable host):
// "10.20.2.0/24" -> "10.20.2.1".
func zoneGateway(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	gw := make(net.IP, len(ip))
	copy(gw, ip)
	gw[len(gw)-1] = 1
	return gw.String()
}

// RestartDnsmasq restarts the rendered dnsmasq unit via systemd. It
// runs only when pool-level config actually changed — hosts.d rides
// inotify, so a periodic no-drift loop must never bounce the daemon.
// kcportald runs as the unprivileged kcportal user, so systemctl needs
// the deploy/pi/kcportald-dnsmasq-restart.path unit (path-activated as
// root) to grant the polkit privilege; when neither the polkit rule nor
// the unit is installed, or systemd refuses, the failure is logged and
// the operator restarts by hand like before — config on disk is already
// correct.
func RestartDnsmasq(log *slog.Logger) {
	out, err := exec.Command("systemctl", "restart", "dnsmasq-kcp.service").CombinedOutput()
	if err != nil {
		log.Warn("dnsmasq restart failed — operator action needed (systemctl restart dnsmasq-kcp)",
			"err", err, "output", strings.TrimSpace(string(out)))
		return
	}
	log.Info("dnsmasq-kcp restarted — pool changes live")
}

// RestartHostapd restarts the Wi-Fi AP unit (hostapd@kcportald) when its
// rendered config changed. hostapd has no config reload: radio-level
// settings require a full restart, which drops clients for a few
// seconds. Same privilege story as RestartDnsmasq: polkit rule + the
// deploy/pi/kcportald-hostapd-restart.path unit; failure = operator
// restart, exactly the manual flow this automates.
func RestartHostapd(log *slog.Logger) {
	out, err := exec.Command("systemctl", "restart", "hostapd@kcportald.service").CombinedOutput()
	if err != nil {
		log.Warn("hostapd restart failed — operator action needed (systemctl restart hostapd@kcportald)",
			"err", err, "output", strings.TrimSpace(string(out)))
		return
	}
	log.Info("hostapd@kcportald restarted — config change live")
}
