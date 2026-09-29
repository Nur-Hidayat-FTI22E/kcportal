// Package config loads app.yaml. Shape follows the fields referenced
// across the design doc (§3.1 DD-01/02/08, §4.1, §7.1 IF-03 for the PoS
// app entry). The reconciler that actually turns this into nft/hostapd/
// dnsmasq config lands in M1 — this package only defines and validates
// the shape for now.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Profile       string       `yaml:"profile"` // "cafe" | "sekolah" | "kantor" (spec P7); MVP is Café-only
	WAN           WANConfig    `yaml:"wan"`
	Zones         []Zone       `yaml:"zones"`
	SSIDs         []SSID       `yaml:"ssids"`
	Apps          []AppEntry   `yaml:"apps"`
	Portal        PortalConfig `yaml:"portal"`
	RetentionDays int          `yaml:"retention_days"` // guest_sessions retention (§8, NFR-PRV-01 default 30)
	// AppsUID is the host uid App Pack containers run as (kcapps). >0
	// wires the DD-14 app_egress chain (default-deny egress for that
	// uid, explicit allows only). 0 = no enforcement (default for
	// deployments without the App Pack).
	AppsUID int `yaml:"apps_uid"`
}

type WANConfig struct {
	Mode string `yaml:"mode"` // "pppoe" | "dhcp" | "static" (DD-08)
	// PPPoE credentials are deliberately NOT here — they live under
	// /data/kcportal/secrets/*, which §7.3 says is never mapped to any
	// application and is written/read only by kcportald itself.
}

// Zone mirrors zones[] referenced throughout §3-4: mark 0=Waiting,
// 1=Admin, 2=POS, 3=Guest in the Café profile (§2.4 listener table).
type Zone struct {
	ID       int             `yaml:"id"`
	Name     string          `yaml:"name"`
	Mark     int             `yaml:"mark"`
	Subnet   string          `yaml:"subnet"` // CIDR, e.g. "10.20.2.0/24" — schema §8 zones.subnet
	Internet bool            `yaml:"internet"`
	LANAllow []LANAllowEntry `yaml:"lan_allow"`
}

type LANAllowEntry struct {
	DstIP string `yaml:"dst_ip"`
	Proto string `yaml:"proto"`
	Port  int    `yaml:"port"`
}

// SSID mirrors the two-BSS Wi-Fi layout of DD-01: Staff on br-lan, Guest
// ("portal") on br-guest — fixed pairing, not reassignable at runtime.
type SSID struct {
	BSS    string `yaml:"bss"` // "wlan0" | "wlan0_1"
	SSID   string `yaml:"ssid"`
	Bridge string `yaml:"bridge"` // "br-lan" | "br-guest"
	Hidden bool   `yaml:"hidden"`
}

// AppEntry mirrors the one App Pack the SDD designs so far: pos-cafe
// (§7.1 IF-03 "Konfigurasi: Env dari app.yaml"). No secret ever lives
// here — printer address is not sensitive.
type AppEntry struct {
	ID          string `yaml:"id"`
	Version     string `yaml:"version"`
	PrinterMode string `yaml:"printer_mode"` // "usb" | "tcp"
	PrinterAddr string `yaml:"printer_addr"` // "/dev/usb/lp0" or "10.20.2.20:9100"
	PaperMM     int    `yaml:"paper_mm"`     // e.g. 58 (POS_PAPER_MM)
}

type PortalConfig struct {
	SessionTTLMinutes int    `yaml:"session_ttl_minutes"`
	UplinkKbps        int    `yaml:"uplink_kbps"`   // FR-CPT-004; doc default 5000 kbps
	DownlinkKbps      int    `yaml:"downlink_kbps"` // FR-CPT-004
	TLSMode           string `yaml:"tls_mode"`      // "t1_local_ca" | "t2_public_acme" (DD-09)
}

// Load reads and validates path. Callers should fall back to Default()
// when this returns an error and no app.yaml exists yet — that is
// DD-15's setup mode, not a fatal condition.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the invariants the design doc states outright. It does
// NOT yet check things M1's reconciler will need to check too (e.g. that
// LANAllow destinations are actually reachable) — that arrives with the
// reconciler itself so the two don't drift apart.
func (c *Config) Validate() error {
	if c.Profile == "" {
		c.Profile = "cafe"
	}
	if c.Profile != "cafe" {
		return fmt.Errorf("config: profile %q not implemented yet — MVP is Café-only (see doc header table)", c.Profile)
	}
	switch c.WAN.Mode {
	case "pppoe", "dhcp", "static":
	default:
		return fmt.Errorf("config: wan.mode %q invalid (want pppoe|dhcp|static, DD-08)", c.WAN.Mode)
	}
	seen := map[int]bool{}
	for _, z := range c.Zones {
		if seen[z.Mark] {
			return fmt.Errorf("config: duplicate zone mark 0x%02x", z.Mark)
		}
		seen[z.Mark] = true
	}
	return nil
}

// Default returns the Café MVP defaults implied by §2.4 (listener table)
// and §4.1 (interface plan), for first boot before app.yaml exists
// (DD-15 setup mode).
func Default() *Config {
	return &Config{
		Profile: "cafe",
		WAN:     WANConfig{Mode: "pppoe"},
		Zones: []Zone{
			// Subnets §4.1 interface plan (waiting uses the router itself,
			// 10.20.99.1, as its gateway per ERR-01).
			{ID: 0, Name: "waiting", Mark: 0x00, Subnet: "10.20.99.0/24", Internet: false},
			{ID: 1, Name: "admin", Mark: 0x01, Subnet: "10.20.1.0/24", Internet: true},
			{ID: 2, Name: "pos", Mark: 0x02, Subnet: "10.20.2.0/24", Internet: true},
			{ID: 3, Name: "guest", Mark: 0x03, Subnet: "10.20.3.0/24", Internet: true},
		},
		SSIDs: []SSID{
			{BSS: "wlan0", SSID: "Staff", Bridge: "br-lan"},
			{BSS: "wlan0_1", SSID: "portal", Bridge: "br-guest"},
		},
		Portal: PortalConfig{
			SessionTTLMinutes: 60,
			UplinkKbps:        5000,
			DownlinkKbps:      5000,
			TLSMode:           "t1_local_ca",
		},
		RetentionDays: 30,
	}
}
