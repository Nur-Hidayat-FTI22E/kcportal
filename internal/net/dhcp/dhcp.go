// Package dhcp renders dnsmasq.conf and the per-device reservation
// files (MOD-DHCP, §4.5). Everything lands in /run/kcportal/dnsmasq
// (tmpfs, PD-4/P-06): the lease file is RAM-only and rebuilt from
// reservations at boot. Waiting is the only dynamic pool on br-lan
// (FR-NET-003, 120 s lease); approved zone pools are static so unknown
// devices can only ever get a Waiting address — no negative tagging
// needed (TV-02).
package dhcp

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ZonePool is one zone's DHCP view.
type ZonePool struct {
	Tag    string // dnsmasq set: tag (z1, z2, guest, waiting)
	Bridge string
	Router string // gateway advertised to clients
	DNS    string // DNS server advertised (usually the router itself)
	// Static pools (approved zones) have empty RangeStart/End and get
	// `dhcp-range=set:<tag>,<subnet>,static`; unknown devices then fall
	// through to the Waiting pool (TV-02).
	RangeStart string
	RangeEnd   string
	Subnet     string
	Lease      string // dnsmasq lease time literal: "120s", "2h", "12h"
}

// Config is the desired state rendered into dnsmasq.conf.
type Config struct {
	UpstreamDNS []string   // no-resolv servers (MVP: plain UDP, DD-16)
	Pools       []ZonePool // order: waiting, then zones, then guest
	LeaseFile   string     // default /run/kcportal/dnsmasq/leases
	HostsDir    string     // default /run/kcportal/dnsmasq/hosts.d
	HookPath    string     // default /usr/lib/kcportal/dhcp-hook

	// Local addresses rendered as address=/name/ip (ERR-01 captive entries).
	LocalDomain string            // kcp.internal
	Addresses   map[string]string // name -> ip, e.g. "admin" -> "192.168.50.1"
}

// Render produces dnsmasq.conf, deterministic like every generator.
func Render(c *Config) ([]byte, error) {
	if len(c.UpstreamDNS) == 0 {
		return nil, fmt.Errorf("dhcp: at least one upstream DNS server required")
	}
	if c.LocalDomain == "" {
		return nil, fmt.Errorf("dhcp: local domain required")
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("user=dnsmasq")
	w("bind-dynamic")
	w("interface=br-lan")
	w("interface=br-guest")
	w("no-resolv")
	for _, s := range c.UpstreamDNS {
		w("server=%s", s)
	}
	w("cache-size=1000")
	w("domain-needed")
	w("bogus-priv")
	w("stop-dns-rebind")
	w("rebind-localhost-ok") // SEC-011
	w("local=/%s/", c.LocalDomain)
	// Map iteration is randomised; sort for byte-identical output (the
	// reconciler's hash check depends on determinism).
	names := make([]string, 0, len(c.Addresses))
	for name := range c.Addresses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w("address=/%s.%s/%s", name, c.LocalDomain, c.Addresses[name])
	}
	w("")
	w("dhcp-authoritative")
	leaseFile := orDefault(c.LeaseFile, "/run/kcportal/dnsmasq/leases")
	hostsDir := orDefault(c.HostsDir, "/run/kcportal/dnsmasq/hosts.d")
	hook := orDefault(c.HookPath, "/usr/lib/kcportal/dhcp-hook")
	w("dhcp-leasefile=%s", leaseFile) // RAM (P-06); rebuilt from reservations
	w("dhcp-hostsdir=%s", hostsDir)   // one file per approved device (inotify)
	w("dhcp-script=%s", hook)
	w("")

	for _, p := range c.Pools {
		w("# pool %s on %s", p.Tag, p.Bridge)
		switch {
		case p.RangeStart != "" && p.RangeEnd != "":
			w("dhcp-range=set:%s,%s,%s,%s,%s", p.Tag, p.RangeStart, p.RangeEnd, p.Subnet, p.Lease)
		case strings.Contains(p.RangeStart, "/"):
			// Static zone pool (TV-02) given as CIDR: the netmask is
			// implied — dnsmasq rejects an explicit mask after a CIDR.
			// Lease time belongs to the per-device dhcp-host line.
			w("dhcp-range=set:%s,%s,static", p.Tag, p.RangeStart)
		case p.RangeStart != "":
			// Static pool with a bare network address needs the explicit
			// netmask (the canonical dnsmasq static form); the lease here
			// is the default for the range, dhcp-host lines override it.
			w("dhcp-range=set:%s,%s,static,%s,%s", p.Tag, p.RangeStart, p.Subnet, p.Lease)
		default:
			return nil, fmt.Errorf("dhcp: pool %s needs a subnet", p.Tag)
		}
		if p.Router != "" {
			w("dhcp-option=tag:%s,option:router,%s", p.Tag, p.Router)
		}
		if p.DNS != "" {
			w("dhcp-option=tag:%s,option:dns-server,%s", p.Tag, p.DNS)
		}
		w("")
	}

	// Captive-portal DHCP option 114 goes ONLY with public certificates
	// (DD-09/T2, ERR-07); T1 local CA must not advertise the captive URL,
	// so it is a comment in the template exactly like the reference.
	w(`# HANYA bila sertifikat publik tersedia (DD-09/T2; ERR-07):`)
	w(`# dhcp-option=tag:guest,114,"https://portal.kcp.internal/portal/api/v1/captive"`)
	return []byte(b.String()), nil
}

// Reservation is one approved device's static lease file content
// (§4.5: `aa:bb:cc:00:00:01,set:z2,10.20.2.11,tablet-kasir,12h`).
type Reservation struct {
	MAC       string
	ZoneTag   string
	IP        string
	Hostname  string
	LeaseTime string // "12h"; empty = infinite
}

// Filename is the per-MAC file name inside hosts.d (hex, no separators).
func (r Reservation) Filename() string {
	return strings.ReplaceAll(strings.ToLower(r.MAC), ":", "") + ".conf"
}

// Line renders the single dnsmasq dhcp-host line.
func (r Reservation) Line() string {
	parts := []string{strings.ToLower(r.MAC), "set:" + r.ZoneTag, r.IP}
	if r.Hostname != "" {
		parts = append(parts, r.Hostname)
	}
	if r.LeaseTime != "" {
		parts = append(parts, r.LeaseTime)
	}
	return strings.Join(parts, ",")
}

// WriteReservations syncs hosts.d/ to exactly the given reservations:
// one file per MAC written atomically (tmp -> rename, §4.5), files for
// MACs no longer approved are removed. dnsmasq's inotify picks up each
// change without a restart. The first return value is how many files
// actually changed (created/updated/removed) — callers use it to skip
// the reload: per-file changes need none (inotify), and an all-quiet
// sync needs none either.
func WriteReservations(dir string, reservations []Reservation) (int, error) {
	changed := 0
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("dhcp: mkdir hosts.d: %w", err)
	}
	want := make(map[string]Reservation, len(reservations))
	for _, r := range reservations {
		if r.MAC == "" || r.IP == "" || r.ZoneTag == "" {
			return 0, fmt.Errorf("dhcp: incomplete reservation %+v", r)
		}
		want[r.Filename()] = r
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("dhcp: read hosts.d: %w", err)
	}
	// Remove stale files first (a device leaving a zone must lose its
	// lease even if a later write fails).
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := want[e.Name()]; !ok {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return changed, fmt.Errorf("dhcp: remove stale reservation %s: %w", e.Name(), err)
			}
			changed++
		}
	}
	for name, r := range want {
		path := filepath.Join(dir, name)
		current, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(current)) == r.Line() {
			continue // unchanged (file carries a trailing newline): don't churn inotify
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(r.Line()+"\n"), 0o640); err != nil {
			return changed, fmt.Errorf("dhcp: write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return changed, fmt.Errorf("dhcp: rename %s: %w", name, err)
		}
		changed++
	}
	return changed, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Default builds the Café MVP pools from §2.4/§4.5 (waiting 120 s on
// br-lan; z1 admin + z2 pos static; guest 2 h on br-guest).
func Default() *Config {
	return &Config{
		UpstreamDNS: []string{"1.1.1.1", "9.9.9.9"}, // MVP plain UDP (DD-16)
		LocalDomain: "kcp.internal",
		Addresses: map[string]string{
			"admin":   "192.168.50.1",
			"pos":     "10.20.2.1",
			"portal":  "10.20.3.1",
			"waiting": "10.20.99.1",
		},
		Pools: []ZonePool{
			{Tag: "waiting", Bridge: "br-lan", RangeStart: "10.20.99.10", RangeEnd: "10.20.99.250", Subnet: "255.255.255.0", Lease: "120s", Router: "10.20.99.1", DNS: "10.20.99.1"},
			{Tag: "z1", Bridge: "br-lan", RangeStart: "192.168.50.0", Subnet: "255.255.255.0", Lease: "12h", Router: "192.168.50.1", DNS: "192.168.50.1"},
			{Tag: "z2", Bridge: "br-lan", RangeStart: "10.20.2.0", Subnet: "255.255.255.0", Lease: "12h", Router: "10.20.2.1", DNS: "10.20.2.1"},
			{Tag: "guest", Bridge: "br-guest", RangeStart: "10.20.3.20", RangeEnd: "10.20.3.250", Subnet: "255.255.255.0", Lease: "2h", Router: "10.20.3.1", DNS: "10.20.3.1"},
		},
	}
}
