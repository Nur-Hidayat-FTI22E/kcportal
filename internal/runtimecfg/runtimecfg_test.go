package runtimecfg

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/net/dhcp"
	"kotacloud-portal/internal/store"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedApprovedDevice(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now()
	if err := store.EnsureSeedZones(db, []store.SeedZone{
		{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true},
		{ID: 2, Name: "pos", Subnet: "10.20.2.0/24", Internet: true},
	}); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if err := store.ApproveDevice(db, "aa:bb:cc:dd:ee:01", 2, "kasir", "test", now); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := store.ReserveLease(db, "aa:bb:cc:dd:ee:01", "10.20.2.11", now); err != nil {
		t.Fatalf("reserve lease: %v", err)
	}
}

// The dnsmasq render must carry the TV-02 shape: Waiting stays the only
// dynamic pool, approved zones go static, approved devices land in
// hosts.d keyed by canonical lowercase MAC.
func TestRenderDnsmasqPoolsAndReservations(t *testing.T) {
	db := testDB(t)
	seedApprovedDevice(t, db)

	out, resv, err := RenderDnsmasq(db, []string{"1.1.1.1"}, map[int]string{1: "z1", 2: "z2"}, "12h")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		"dhcp-range=set:waiting,10.20.99.10,10.20.99.250",
		"dhcp-range=set:guest,10.20.3.20,10.20.3.250",
		// Zone subnets come from state.db as CIDR; the renderer converts
		// them to dnsmasq's canonical bare-network+mask static form.
		"dhcp-range=set:z2,10.20.2.0,static,255.255.255.0,12h",
		"dhcp-option=tag:z2,option:router,10.20.2.1",
		"dhcp-hostsdir=",
		"dhcp-script=",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dnsmasq.conf missing %q\n%s", want, s)
		}
	}
	if len(resv) != 1 {
		t.Fatalf("reservations = %d, want 1", len(resv))
	}
	if resv[0].MAC != "aa:bb:cc:dd:ee:01" || resv[0].IP != "10.20.2.11" || resv[0].ZoneTag != "z2" {
		t.Errorf("reservation = %+v", resv[0])
	}
	// Determinism: two renders must be byte-identical.
	out2, _, err := RenderDnsmasq(db, []string{"1.1.1.1"}, map[int]string{1: "z1", 2: "z2"}, "12h")
	if err != nil {
		t.Fatalf("render 2: %v", err)
	}
	if string(out) != string(out2) {
		t.Error("render is not deterministic")
	}
}

// Waiting-zone devices and non-approved states must never leak into
// hosts.d (TV-02: unknown devices only ever get a Waiting address).
func TestRenderDnsmasqSkipsUnapproved(t *testing.T) {
	db := testDB(t)
	seedApprovedDevice(t, db)
	now := time.Now()
	// A second device, approved into admin but without a lease IP yet.
	if err := store.ApproveDevice(db, "aa:bb:cc:dd:ee:02", 1, "", "test", now); err != nil {
		t.Fatalf("approve 2: %v", err)
	}
	// A waiting device (UpsertSeenDevice) that still holds a cache lease.
	if _, err := store.UpsertSeenDevice(db, "aa:bb:cc:dd:ee:03", "phone", "br-lan", now); err != nil {
		t.Fatalf("seen: %v", err)
	}
	if err := store.UpsertLease(db, "aa:bb:cc:dd:ee:03", "10.20.99.50", 2*time.Hour, now); err != nil {
		t.Fatalf("lease: %v", err)
	}

	_, resv, err := RenderDnsmasq(db, []string{"1.1.1.1"}, map[int]string{1: "z1", 2: "z2"}, "12h")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, r := range resv {
		if r.MAC == "aa:bb:cc:dd:ee:03" {
			t.Errorf("waiting device leaked into reservations: %+v", r)
		}
		if r.MAC == "aa:bb:cc:dd:ee:02" {
			t.Errorf("approved device without lease IP leaked into reservations: %+v", r)
		}
	}
}

func TestZoneGateway(t *testing.T) {
	for in, want := range map[string]string{
		"10.20.2.0/24":    "10.20.2.1",
		"192.168.50.0/24": "192.168.50.1",
		"10.20.99.0/24":   "10.20.99.1",
		"not-a-cidr":      "",
	} {
		if got := zoneGateway(in); got != want {
			t.Errorf("zoneGateway(%q) = %q, want %q", in, got, want)
		}
	}
}

// WriteReservations converges and does not rewrite unchanged files —
// assert mtime stability across an identical second sync.
func TestWriteReservationsNoChurn(t *testing.T) {
	dir := t.TempDir()
	r := []dhcp.Reservation{{MAC: "aa:bb:cc:dd:ee:01", ZoneTag: "z2", IP: "10.20.2.11", LeaseTime: "12h"}}
	if _, err := dhcp.WriteReservations(dir, r); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	f := filepath.Join(dir, "aabbccddee01.conf")
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("reservation file missing: %v", err)
	}
	st1, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dhcp.WriteReservations(dir, r); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	st2, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("unchanged reservation file was rewritten (inotify churn)")
	}
}

// Hostapd render must reject without a radio — on CI/sandbox there is
// none, which is exactly the fail-closed path being asserted. The Pi
// path (radio present) is exercised live by the deployment.
func TestRenderHostapdFailClosedWithoutRadio(t *testing.T) {
	if _, ok := DetectIFace("wlan0"); ok {
		t.Skip("wlan0 present on this host — failure path not testable here")
	}
	if _, err := RenderHostapd("Cafe-Staff", "portal", "psk-from-secrets"); err == nil {
		t.Fatal("want error when no radio exists")
	}
}

// TestRequireBridgesFailClosed asserts the production guard: without
// br-lan/br-guest the renderer refuses — never renders a config that
// would strand hostapd/dnsmasq on missing devices.
func TestRequireBridgesFailClosed(t *testing.T) {
	have := DetectBridges("br-lan", "br-guest")
	if have["br-lan"] && have["br-guest"] {
		t.Skip("bridges exist on this host (deployed Pi?) — failure path not testable")
	}
	if err := RequireBridges(nil); err == nil {
		t.Fatal("want error when bridges are missing")
	}
}
