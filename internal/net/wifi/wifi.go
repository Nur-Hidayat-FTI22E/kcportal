// Package wifi renders hostapd.conf from desired state (MOD-WIFI, §4.4).
// The layout follows the design doc verbatim: one file, two BSS
// (BSS0 Staff -> br-lan, BSS1 Guest "portal" -> br-guest, DD-01 fixed
// pairing), one band for all BSS (LIM-05), PSK injected at render time
// from the secrets store and never persisted in the plan (§7.3 secrets).
package wifi

import (
	"fmt"
	"strings"
)

// BSS is one virtual access point inside the config.
type BSS struct {
	Iface      string // "wlan0" (BSS0) or "wlan0_1" (BSS1)
	SSID       string
	Bridge     string // DD-01: br-lan | br-guest, fixed at first boot
	Open       bool   // true = guest portal BSS (wpa=0, FR-WIF-010)
	Passphrase string // WPA2 PSK; empty for Open. Injected from secrets at render.
	Hidden     bool
}

// Radio is the physical card shared by every BSS.
type Radio struct {
	CountryCode string // FR-WIF-006: ID
	HWMode      string // "a" (5 GHz non-DFS) or "g" (2.4 GHz) — one band for all BSS, LIM-05
	Channel     int    // lowest non-DFS channel the regulation allows
	VHT80       bool   // 80 MHz on 5 GHz (vht_oper_chwidth=1)
	MaxStations int    // FR-WIF-007, SP-001 final (default 16)
}

// Config is the desired state rendered into hostapd.conf.
type Config struct {
	Radio Radio
	BSS   []BSS // exactly two: Staff, then Guest (DD-01)
	Venue string

	// CtrlDir is hostapd's ctrl_interface directory (/run/hostapd).
	CtrlDir string
}

// Validate guards the DD-01 invariants before anything hits disk.
func (c *Config) Validate() error {
	if len(c.BSS) != 2 {
		return fmt.Errorf("wifi: exactly two BSS required (DD-01), got %d", len(c.BSS))
	}
	if c.BSS[0].Bridge == c.BSS[1].Bridge {
		return fmt.Errorf("wifi: both BSS on %s — DD-01 requires one on br-lan and one on br-guest", c.BSS[0].Bridge)
	}
	if c.BSS[0].Open {
		return fmt.Errorf("wifi: BSS0 (Staff) must be WPA2, not open")
	}
	if !c.BSS[1].Open {
		return fmt.Errorf("wifi: BSS1 (Guest portal) must be open (FR-WIF-010)")
	}
	if c.BSS[1].Passphrase != "" {
		return fmt.Errorf("wifi: open BSS must not carry a passphrase")
	}
	if strings.TrimSpace(c.BSS[0].Passphrase) == "" {
		return fmt.Errorf("wifi: staff PSK empty — render must inject it from /data/kcportal/secrets")
	}
	if c.Radio.CountryCode == "" {
		return fmt.Errorf("wifi: country_code required (FR-WIF-006)")
	}
	if c.Radio.HWMode != "a" && c.Radio.HWMode != "g" {
		return fmt.Errorf("wifi: hw_mode %q invalid (a|g)", c.Radio.HWMode)
	}
	return nil
}

// Render produces hostapd.conf. Deterministic like the nft renderer:
// identical configs render byte-identical files (reconciler hash check).
func Render(c *Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	ctrl := c.CtrlDir
	if ctrl == "" {
		ctrl = "/run/hostapd"
	}
	maxSta := c.Radio.MaxStations
	if maxSta <= 0 {
		maxSta = 16
	}

	w("ctrl_interface=%s", ctrl)
	w("ctrl_interface_group=kcportal")
	w("country_code=%s", c.Radio.CountryCode)
	w("ieee80211d=1")
	w("interface=%s", c.BSS[0].Iface)
	w("driver=nl80211")
	w("hw_mode=%s", c.Radio.HWMode)
	w("channel=%d", c.Radio.Channel)
	w("ieee80211n=1")
	if c.Radio.HWMode == "a" {
		w("ieee80211ac=1")
		if c.Radio.VHT80 {
			// §4.4: channel 36 + seg0 42 for 80 MHz. Center = primary + 6
			// within a 20 MHz-aligned 80 MHz block (36..48 -> 42, 149..161
			// -> 155). The reconciler validates the pair against `iw reg`
			// output when it lands.
			w("vht_oper_chwidth=1")
			w("vht_oper_centr_freq_seg0_idx=%d", c.Radio.Channel+6)
		}
	}
	w("wmm_enabled=1")
	w("max_num_sta=%d", maxSta)
	w("ap_max_inactivity=300")
	w("disassoc_low_ack=1")
	w("")

	// BSS0 — Staff (Bouncer: enforce). Radio-level interface already
	// declares it; this block carries the security settings.
	w("# BSS0 — Staff (Bouncer: enforce) -> %s", c.BSS[0].Bridge)
	w("ssid=%s", c.BSS[0].SSID)
	w("bridge=%s", c.BSS[0].Bridge)
	w("ap_isolate=1")
	w("auth_algs=1")
	w("wpa=2")
	w("wpa_key_mgmt=WPA-PSK")
	w("rsn_pairwise=CCMP")
	w("wpa_passphrase=%s", c.BSS[0].Passphrase) // from secrets at render; file is 0600 on tmpfs (PD-4)
	w("")

	// BSS1 — Guest (Bouncer: portal), DD-01.
	w("# BSS1 — Guest (Bouncer: portal) -> %s   (DD-01)", c.BSS[1].Bridge)
	w("bss=%s", c.BSS[1].Iface)
	w("ssid=%s", c.BSS[1].SSID)
	w("bridge=%s", c.BSS[1].Bridge)
	w("ap_isolate=1")
	w("wpa=0") // open (FR-WIF-010); OWE only if SP-001 proves firmware support
	if c.BSS[1].Hidden {
		w("ignore_broadcast_ssid=1")
	}
	return []byte(b.String()), nil
}

// Default builds the Café MVP config (staff PSK injected separately).
func Default(venue, staffPSK string) *Config {
	return &Config{
		Venue: venue,
		Radio: Radio{CountryCode: "ID", HWMode: "a", Channel: 36, VHT80: true, MaxStations: 16},
		BSS: []BSS{
			{Iface: "wlan0", SSID: venue + "-Staff", Bridge: "br-lan", Passphrase: staffPSK},
			{Iface: "wlan0_1", SSID: venue + "-WiFi", Bridge: "br-guest", Open: true},
		},
	}
}
