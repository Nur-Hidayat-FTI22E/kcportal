package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUpsertSeenDeviceInsertsWaiting(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	inserted, err := UpsertSeenDevice(db, "AA:BB:CC:DD:0E:01", "tablet-kasir", "br-lan", now)
	if err != nil {
		t.Fatalf("UpsertSeenDevice: %v", err)
	}
	if !inserted {
		t.Fatal("first sighting must report inserted=true")
	}
	counts, _ := CountDevicesByState(db)
	if counts["waiting"] != 1 {
		t.Fatalf("state counts = %v, want waiting:1", counts)
	}
	// MAC must be stored canonically lower-case.
	var mac string
	if err := db.QueryRow(`SELECT mac FROM devices`).Scan(&mac); err != nil {
		t.Fatalf("query: %v", err)
	}
	if mac != "aa:bb:cc:dd:0e:01" {
		t.Fatalf("mac = %q, want lower-case canonical form", mac)
	}
}

func TestUpsertSeenDeviceRefreshesWithoutDuplicating(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	if _, err := UpsertSeenDevice(db, "aa:bb:cc:dd:0e:02", "printer", "br-lan", now); err != nil {
		t.Fatalf("first: %v", err)
	}
	later := now.Add(2 * time.Minute)
	inserted, err := UpsertSeenDevice(db, "aa:bb:cc:dd:0e:02", "printer-lan", "br-lan", later)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if inserted {
		t.Error("re-sighting must report inserted=false")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM devices`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("devices = %d (%v), want 1", n, err)
	}
	var lastSeen int64
	if err := db.QueryRow(`SELECT last_seen FROM devices`).Scan(&lastSeen); err != nil {
		t.Fatalf("query: %v", err)
	}
	if lastSeen != later.Unix() {
		t.Errorf("last_seen not refreshed")
	}
	var hostname string
	if err := db.QueryRow(`SELECT hostname FROM devices`).Scan(&hostname); err != nil {
		t.Fatalf("query: %v", err)
	}
	if hostname != "printer-lan" {
		t.Errorf("hostname = %q, want printer-lan (hook refreshes the name)", hostname)
	}
}

func TestUpsertSeenDeviceFloodCapEvictsOldest(t *testing.T) {
	db := openTestDB(t)
	base := time.Now().Add(-time.Hour)

	// Fill the table to the cap plus one; the oldest non-approved row
	// must be evicted and the error must mention bouncer.flood.
	for i := 0; i <= FloodCap; i++ {
		mac := "aa:bb:cc:dd:0e:" + strings.Repeat("0", 0) + macSuffix(i)
		_, err := UpsertSeenDevice(db, mac, "", "br-lan", base.Add(time.Duration(i)*time.Second))
		if i == FloodCap {
			if err == nil || !strings.Contains(err.Error(), "bouncer.flood") {
				t.Fatalf("row %d: want bouncer.flood error, got %v", i, err)
			}
		} else if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM devices`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != FloodCap {
		t.Fatalf("devices = %d after eviction, want %d", n, FloodCap)
	}
}

// macSuffix renders the last octet of a test MAC.
func macSuffix(i int) string {
	const hex = "0123456789abcdef"
	if i < 256 {
		return string(hex[i/16]) + string(hex[i%16])
	}
	// Beyond 255 devices we would exceed the cap test anyway; keep it
	// deterministic regardless.
	return "ff" + string(hex[i%16])
}

func TestApprovedDevicesSurviveFloodEviction(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSeedZones(db, []SeedZone{{ID: 1, Name: "pos", Subnet: "10.20.2.0/24", Internet: true}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	base := time.Now().Add(-time.Hour)

	if err := ApproveDevice(db, "aa:bb:cc:dd:0e:aa", 1, "", "admin", base); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Oldest row overall is the approved one, but eviction must skip it.
	for i := 0; i <= FloodCap; i++ {
		_, _ = UpsertSeenDevice(db, "aa:bb:cc:dd:0e:"+macSuffix(i), "", "br-lan", base.Add(time.Duration(i+1)*time.Second))
	}
	var state string
	err := db.QueryRow(`SELECT state FROM devices WHERE mac = 'aa:bb:cc:dd:0e:aa'`).Scan(&state)
	if err != nil {
		t.Fatalf("approved device was evicted: %v", err)
	}
	if state != "approved" {
		t.Fatalf("state = %q, want approved", state)
	}
}

func TestUpsertLeaseRespectsReservation(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	if err := ReserveLease(db, "aa:bb:cc:dd:0e:0b", "10.20.2.11", now); err != nil {
		t.Fatalf("ReserveLease: %v", err)
	}
	// A hook event for the same MAC must not move the pinned IP.
	if err := UpsertLease(db, "aa:bb:cc:dd:0e:0b", "10.20.99.50", time.Hour, now); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	var ip string
	var reserved int
	if err := db.QueryRow(`SELECT ip4, reserved FROM ip_leases WHERE mac = 'aa:bb:cc:dd:0e:0b'`).Scan(&ip, &reserved); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ip != "10.20.2.11" || reserved != 1 {
		t.Fatalf("lease = %s reserved=%d; reservation was clobbered", ip, reserved)
	}
}

func TestUpsertAndRemoveLease(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	if err := UpsertLease(db, "aa:bb:cc:dd:0e:0c", "10.20.99.51", time.Hour, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := UpsertLease(db, "aa:bb:cc:dd:0e:0c", "10.20.99.51", time.Hour, now); err != nil {
		t.Fatalf("upsert again: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM ip_leases`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("leases = %d (%v), want 1 (upsert not duplicate)", n, err)
	}

	if err := RemoveLease(db, "aa:bb:cc:dd:0e:0c"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(1) FROM ip_leases`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("leases after del = %d (%v), want 0", n, err)
	}
}

func TestRemoveLeaseKeepsReservations(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	if err := ReserveLease(db, "aa:bb:cc:dd:0e:0d", "10.20.2.12", now); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := RemoveLease(db, "aa:bb:cc:dd:0e:0d"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM ip_leases WHERE mac = 'aa:bb:cc:dd:0e:0d'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("reservation survived=%d (%v), want 1", n, err)
	}
}

func TestFlushExpiredDevices(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSeedZones(db, []SeedZone{{ID: 1, Name: "pos", Subnet: "10.20.2.0/24", Internet: true}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	now := time.Now()

	if err := ApproveDevice(db, "aa:bb:cc:dd:0e:0e", 1, "", "admin", now); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Backdate the approval's expiry.
	past := now.Add(-time.Hour).Unix()
	if _, err := db.Exec(`UPDATE devices SET expires_at = ? WHERE mac = 'aa:bb:cc:dd:0e:0e'`, past); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := ApproveDevice(db, "aa:bb:cc:dd:0e:0f", 1, "", "admin", now); err != nil {
		t.Fatalf("approve 2: %v", err)
	}

	demoted, err := FlushExpiredDevices(db, now)
	if err != nil {
		t.Fatalf("FlushExpiredDevices: %v", err)
	}
	if len(demoted) != 1 || demoted[0] != "aa:bb:cc:dd:0e:0e" {
		t.Fatalf("demoted = %v, want only the expired device", demoted)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM devices WHERE mac = 'aa:bb:cc:dd:0e:0e'`).Scan(&state); err != nil {
		t.Fatalf("query: %v", err)
	}
	if state != "expired" {
		t.Fatalf("state = %q, want expired", state)
	}
	// Non-expired device untouched.
	if err := db.QueryRow(`SELECT state FROM devices WHERE mac = 'aa:bb:cc:dd:0e:0f'`).Scan(&state); err != nil || state != "approved" {
		t.Fatalf("live approval disturbed: %q %v", state, err)
	}
}

func TestUpsertLeaseRejectsBadIP(t *testing.T) {
	db := openTestDB(t)
	err := UpsertLease(db, "aa:bb:cc:dd:0e:10", "not-an-ip", time.Hour, time.Now())
	if err == nil {
		t.Fatal("bad lease IP must be rejected")
	}
}

func TestUpsertSeenDeviceEmptyMAC(t *testing.T) {
	db := openTestDB(t)
	_, err := UpsertSeenDevice(db, "", "", "br-lan", time.Now())
	if err == nil {
		t.Fatal("empty MAC must be rejected")
	}
	if !errors.Is(err, err) {
		t.Fatal("unreachable guard to keep errors import honest")
	}
}
