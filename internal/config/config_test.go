package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeYAML is the standard fixture writer: a temp app.yaml with content.
func writeYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestDefaultMatchesCafeMVPSpec pins Default() to the values the design
// doc states: §2.4 zone marks (0=Waiting..3=Guest), §4.1 DD-01 BSS/bridge
// pairing, FR-CPT-004 bandwidth defaults, DD-15 setup mode defaults.
func TestDefaultMatchesCafeMVPSpec(t *testing.T) {
	c := Default()

	if c.Profile != "cafe" {
		t.Fatalf("profile = %q, want cafe", c.Profile)
	}
	if c.WAN.Mode != "pppoe" {
		t.Fatalf("wan.mode = %q, want pppoe", c.WAN.Mode)
	}

	wantZones := []struct {
		id       int
		name     string
		mark     int
		internet bool
	}{
		{0, "waiting", 0x00, false}, // Waiting zone never gets internet (§2.4)
		{1, "admin", 0x01, true},
		{2, "pos", 0x02, true},
		{3, "guest", 0x03, true},
	}
	if len(c.Zones) != len(wantZones) {
		t.Fatalf("got %d zones, want %d", len(c.Zones), len(wantZones))
	}
	for i, w := range wantZones {
		z := c.Zones[i]
		if z.ID != w.id || z.Name != w.name || z.Mark != w.mark || z.Internet != w.internet {
			t.Errorf("zone[%d] = %+v, want {id:%d name:%s mark:0x%02x internet:%v}",
				i, z, w.id, w.name, w.mark, w.internet)
		}
	}

	// DD-01: BSS->bridge pairing is fixed, not reassignable.
	wantBridges := map[string]string{"wlan0": "br-lan", "wlan0_1": "br-guest"}
	if len(c.SSIDs) != len(wantBridges) {
		t.Fatalf("got %d ssids, want %d", len(c.SSIDs), len(wantBridges))
	}
	for _, s := range c.SSIDs {
		if wantBridges[s.BSS] != s.Bridge {
			t.Errorf("ssid %q on bridge %q, want %q (DD-01)", s.BSS, s.Bridge, wantBridges[s.BSS])
		}
	}

	if c.Portal.SessionTTLMinutes != 60 {
		t.Errorf("session_ttl = %d, want 60", c.Portal.SessionTTLMinutes)
	}
	if c.Portal.UplinkKbps != 5000 || c.Portal.DownlinkKbps != 5000 {
		t.Errorf("bandwidth = %d/%d kbps, want 5000/5000 (FR-CPT-004)",
			c.Portal.UplinkKbps, c.Portal.DownlinkKbps)
	}
	if c.Portal.TLSMode != "t1_local_ca" {
		t.Errorf("tls_mode = %q, want t1_local_ca (DD-09 pilot choice)", c.Portal.TLSMode)
	}
	if c.RetentionDays != 30 {
		t.Errorf("retention_days = %d, want 30 (NFR-PRV-01)", c.RetentionDays)
	}
}

// TestDefaultIsValid: cmd/kcportald feeds Default() straight into the
// runtime, so it must pass Validate on its own.
func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() fails its own validation: %v", err)
	}
}

func TestLoadValidYAML(t *testing.T) {
	path := writeYAML(t, `
profile: cafe
wan:
  mode: dhcp
zones:
  - id: 0
    name: waiting
    mark: 0
    internet: false
  - id: 3
    name: guest
    mark: 3
    internet: true
    lan_allow:
      - dst_ip: 10.20.2.20
        proto: tcp
        port: 9100
ssids:
  - bss: wlan0
    ssid: Staff
    bridge: br-lan
  - bss: wlan0_1
    ssid: portal
    bridge: br-guest
    hidden: true
apps:
  - id: pos-cafe
    version: 1.0.0
    printer_mode: tcp
    printer_addr: 10.20.2.20:9100
    paper_mm: 58
portal:
  session_ttl_minutes: 120
  uplink_kbps: 2000
  downlink_kbps: 8000
  tls_mode: t2_public_acme
retention_days: 14
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.WAN.Mode != "dhcp" {
		t.Errorf("wan.mode = %q, want dhcp", c.WAN.Mode)
	}
	if len(c.Zones) != 2 {
		t.Fatalf("got %d zones, want 2", len(c.Zones))
	}
	guest := c.Zones[1]
	if len(guest.LANAllow) != 1 || guest.LANAllow[0].Port != 9100 {
		t.Errorf("guest lan_allow = %+v, want one tcp/9100 rule (POS printer, §4.3)", guest.LANAllow)
	}
	if !c.SSIDs[1].Hidden {
		t.Error("portal SSID should parse hidden: true")
	}
	app := c.Apps[0]
	if app.ID != "pos-cafe" || app.PrinterMode != "tcp" || app.PrinterAddr != "10.20.2.20:9100" || app.PaperMM != 58 {
		t.Errorf("app entry = %+v", app)
	}
	if c.Portal.SessionTTLMinutes != 120 || c.Portal.DownlinkKbps != 8000 || c.Portal.TLSMode != "t2_public_acme" {
		t.Errorf("portal = %+v", c.Portal)
	}
	if c.RetentionDays != 14 {
		t.Errorf("retention_days = %d, want 14", c.RetentionDays)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load on a missing file must return an error (caller falls back to Default, DD-15)")
	}
	if !strings.Contains(err.Error(), "config: read") {
		t.Fatalf("error %q should mention \"config: read\"", err)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeYAML(t, "profile: [unclosed")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load on malformed YAML must return an error")
	}
	if !strings.Contains(err.Error(), "config: parse") {
		t.Fatalf("error %q should mention \"config: parse\"", err)
	}
}

func TestValidateEmptyProfileBecomesCafe(t *testing.T) {
	c := &Config{WAN: WANConfig{Mode: "pppoe"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Profile != "cafe" {
		t.Fatalf("empty profile should default to cafe, got %q", c.Profile)
	}
}

func TestValidateRejectsUnimplementedProfile(t *testing.T) {
	for _, profile := range []string{"sekolah", "kantor", "lab"} {
		c := &Config{Profile: profile, WAN: WANConfig{Mode: "pppoe"}}
		err := c.Validate()
		if err == nil {
			t.Fatalf("profile %q must be rejected — MVP is Café-only", profile)
		}
		if !strings.Contains(err.Error(), "not implemented yet") {
			t.Errorf("profile %q: error %q should mention \"not implemented yet\"", profile, err)
		}
	}
}

func TestValidateRejectsBadWANMode(t *testing.T) {
	c := &Config{WAN: WANConfig{Mode: "wifi"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("wan.mode \"wifi\" must be rejected")
	}
	if !strings.Contains(err.Error(), "pppoe|dhcp|static") {
		t.Fatalf("error %q should list the valid modes", err)
	}
}

func TestValidateRejectsDuplicateZoneMark(t *testing.T) {
	c := &Config{
		WAN: WANConfig{Mode: "pppoe"},
		Zones: []Zone{
			{Name: "pos", Mark: 0x02},
			{Name: "pos-alias", Mark: 0x02}, // two zones can't share a fwmark (§4.3)
		},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("duplicate zone mark must be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate zone mark") {
		t.Fatalf("error %q should mention \"duplicate zone mark\"", err)
	}
}

func TestValidateAllowsDistinctZoneMarks(t *testing.T) {
	c := &Config{
		WAN: WANConfig{Mode: "static"},
		Zones: []Zone{
			{Name: "waiting", Mark: 0x00},
			{Name: "admin", Mark: 0x01},
			{Name: "pos", Mark: 0x02},
			{Name: "guest", Mark: 0x03},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("four distinct marks should validate: %v", err)
	}
}
