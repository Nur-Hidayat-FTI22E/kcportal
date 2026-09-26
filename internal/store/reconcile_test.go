package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func openSeeded(t *testing.T) *sql.DB {
	t.Helper()
	db := openTestDB(t)
	if err := EnsureSeedZones(db, []SeedZone{
		// No waiting row: mark 0x00 is virtual (devices.state), ids start at 1.
		{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true},
		{ID: 2, Name: "pos", Subnet: "10.20.2.0/24", Internet: true},
		{ID: 3, Name: "guest", Subnet: "10.20.3.0/24", Internet: true},
	}); err != nil {
		t.Fatalf("EnsureSeedZones: %v", err)
	}
	return db
}

func TestEnsureSeedZonesUpserts(t *testing.T) {
	db := openTestDB(t)
	zones := []SeedZone{
		{ID: 2, Name: "pos", Subnet: "10.20.2.0/24", Internet: true},
	}
	if err := EnsureSeedZones(db, zones); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// Second seed with a changed name must update in place, not fail on
	// the PK and not duplicate.
	zones[0].Name = "pos-renamed"
	if err := EnsureSeedZones(db, zones); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM zones WHERE id = 2`).Scan(&name); err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "pos-renamed" {
		t.Fatalf("zone name = %q, want pos-renamed (config change must propagate)", name)
	}
}

func TestLoadPlanSnapshot(t *testing.T) {
	db := openSeeded(t)
	now := time.Now()

	if err := ApproveDevice(db, "aa:bb:cc:dd:00:01", 2, "POS terminal", "admin", now); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	if err := ReserveLease(db, "aa:bb:cc:dd:00:01", "10.20.2.50", now); err != nil {
		t.Fatalf("ReserveLease: %v", err)
	}
	if err := StartGuestSession(db, "aa:bb:cc:dd:00:02", time.Hour, now); err != nil {
		t.Fatalf("StartGuestSession: %v", err)
	}
	// A blocked device and a closed/expired session must stay out of the plan.
	if err := ApproveDevice(db, "aa:bb:cc:dd:00:03", 3, "", "admin", now); err != nil {
		t.Fatalf("ApproveDevice second: %v", err)
	}
	if err := BlockDevice(db, "aa:bb:cc:dd:00:03", "admin", now); err != nil {
		t.Fatalf("BlockDevice: %v", err)
	}

	snap, err := LoadPlan(db, now)
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}

	if len(snap.Zones) != 3 {
		t.Fatalf("zones = %d, want 3 (waiting is virtual, not a row)", len(snap.Zones))
	}
	if len(snap.Devices) != 1 || snap.Devices[0].MAC != "aa:bb:cc:dd:00:01" || snap.Devices[0].ZoneID != 2 {
		t.Fatalf("devices = %+v, want only the approved POS device", snap.Devices)
	}
	if len(snap.Guests) != 1 || snap.Guests[0].MAC != "aa:bb:cc:dd:00:02" {
		t.Fatalf("guests = %+v, want only the open session", snap.Guests)
	}
	if len(snap.Bindings) != 1 || snap.Bindings[0].IP.String() != "10.20.2.50" {
		t.Fatalf("bindings = %+v, want the reserved lease", snap.Bindings)
	}
}

func TestApproveUnknownZoneFails(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSeedZones(db, []SeedZone{{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := ApproveDevice(db, "aa:bb:cc:dd:00:04", 99, "", "admin", time.Now())
	if err == nil {
		t.Fatal("approving into a nonexistent zone must fail (zones not seeded)")
	}
}

func TestBlockUnknownDeviceFails(t *testing.T) {
	db := openTestDB(t)
	err := BlockDevice(db, "aa:bb:cc:dd:00:05", "admin", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("BlockDevice on unknown MAC = %v, want ErrNotFound", err)
	}
}

func TestReApproveRezones(t *testing.T) {
	db := openSeeded(t)
	now := time.Now()

	if err := ApproveDevice(db, "aa:bb:cc:dd:00:06", 2, "", "admin", now); err != nil {
		t.Fatalf("approve into pos: %v", err)
	}
	if err := ApproveDevice(db, "aa:bb:cc:dd:00:06", 3, "moved to guest", "admin", now); err != nil {
		t.Fatalf("re-approve into guest: %v", err)
	}
	snap, err := LoadPlan(db, now)
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if len(snap.Devices) != 1 || snap.Devices[0].ZoneID != 3 {
		t.Fatalf("devices = %+v, want the device re-zoned to 3", snap.Devices)
	}
}

func TestGuestSessionLifecycle(t *testing.T) {
	db := openSeeded(t)
	now := time.Now()

	if err := StartGuestSession(db, "aa:bb:cc:dd:00:07", 30*time.Minute, now); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := StartGuestSession(db, "aa:bb:cc:dd:00:07", -time.Minute, now); err == nil {
		t.Fatal("negative TTL must be rejected")
	}
	snap, _ := LoadPlan(db, now)
	if len(snap.Guests) != 1 {
		t.Fatalf("guests = %d, want 1", len(snap.Guests))
	}

	if err := CloseGuestSessions(db, "aa:bb:cc:dd:00:07", now); err != nil {
		t.Fatalf("close: %v", err)
	}
	snap, _ = LoadPlan(db, now)
	if len(snap.Guests) != 0 {
		t.Fatalf("guests = %d after close, want 0", len(snap.Guests))
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	db := openTestDB(t)

	if _, err := GetSetting(db, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSetting(missing) = %v, want ErrNotFound", err)
	}
	if err := SetSetting(db, "ruleset_sha256", "abc"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := SetSetting(db, "ruleset_sha256", "def"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}
	v, err := GetSetting(db, "ruleset_sha256")
	if err != nil || v != "def" {
		t.Fatalf("GetSetting = %q, %v; want def, nil", v, err)
	}
}

func TestAuditChainLinks(t *testing.T) {
	db := openSeeded(t)
	now := time.Now()

	if err := ApproveDevice(db, "aa:bb:cc:dd:00:08", 1, "first", "admin", now); err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	if err := ApproveDevice(db, "aa:bb:cc:dd:00:09", 1, "second", "admin", now); err != nil {
		t.Fatalf("approve 2: %v", err)
	}

	rows := func() [][]byte {
		t.Helper()
		rs, err := db.Query(`SELECT prev_hash, hash FROM audit_log ORDER BY id`)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		defer rs.Close()
		var out [][]byte
		for rs.Next() {
			var prev, hash []byte
			if err := rs.Scan(&prev, &hash); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, prev, hash)
		}
		return out
	}()

	if len(rows) != 4 { // 2 rows × (prev, hash)
		t.Fatalf("audit rows = %d pairs, want 2", len(rows)/2)
	}
	// First row's prev is the genesis anchor; second row's prev must be
	// the first row's hash — that is the tamper-evidence chain.
	if string(rows[0]) != "genesis" {
		t.Fatalf("first prev_hash = %q, want genesis", rows[0])
	}
	if string(rows[2]) != string(rows[1]) {
		t.Fatal("audit chain broken: row 2 prev_hash != row 1 hash")
	}
}
