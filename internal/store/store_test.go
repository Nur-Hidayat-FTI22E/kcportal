package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// openTestDB opens a fresh state.db in t.TempDir() and fails the test on
// error — every test below needs a migrated DB anyway.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) sql.Result {
	t.Helper()
	res, err := db.Exec(query, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
	return res
}

// TestOpenMigratesAllTables verifies the embedded 0001_base.sql actually
// ran: every table from the Appendix D+H schema exists.
func TestOpenMigratesAllTables(t *testing.T) {
	db := openTestDB(t)

	for _, table := range []string{
		"zones", "ssids", "devices", "vpn_tunnels", "audit_log",
		"profile_state", "apps", "guest_sessions", "settings",
		"ip_leases", "vouchers", "command_log", "schema_migrations",
	} {
		var name string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after migration: %v", table, err)
		}
	}
}

// TestMigrationRecordedInSchemaMigrations guards the reopen path: 0001
// must be recorded so a second Open doesn't replay it.
func TestMigrationRecordedInSchemaMigrations(t *testing.T) {
	db := openTestDB(t)

	var count int
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM schema_migrations WHERE version = '0001_base.sql'`,
	).Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count != 1 {
		t.Fatalf("0001_base.sql recorded %d times, want 1", count)
	}
}

// TestOpenIsIdempotent is the regression test for migrate()'s
// already-applied check: opening the same state.db twice must succeed and
// must not duplicate rows or fail on CREATE TABLE.
func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	db1, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	mustExec(t, db1, `INSERT INTO zones (id, name, subnet) VALUES (1, 'staff', '10.20.1.0/24')`)
	db1.Close()

	db2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open on an already-migrated db: %v", err)
	}
	defer db2.Close()

	var zones int
	if err := db2.QueryRow(`SELECT COUNT(1) FROM zones`).Scan(&zones); err != nil {
		t.Fatalf("count zones: %v", err)
	}
	if zones != 1 {
		t.Fatalf("zones count = %d after reopen, want 1 (data must survive)", zones)
	}
	var versions int
	if err := db2.QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if versions != 1 {
		t.Fatalf("schema_migrations has %d rows after reopen, want 1", versions)
	}
}

// TestOpenSetsWALJournalMode pins §8: state.db must run WAL — a DSN typo
// would silently fall back to the SQLite default (delete) and the
// power-loss story in the design doc breaks.
func TestOpenSetsWALJournalMode(t *testing.T) {
	db := openTestDB(t)

	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal (§8)", mode)
	}
}

// TestDevicesStateEnumEnforced re-proves the CHECK the README says was
// verified by hand: devices.state only accepts the documented enum.
func TestDevicesStateEnumEnforced(t *testing.T) {
	db := openTestDB(t)
	mustExec(t, db, `INSERT INTO zones (id, name, subnet) VALUES (1, 'guest', '10.20.3.0/24')`)

	now := time.Now().Unix()
	mustExec(t, db,
		`INSERT INTO devices (mac, state, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:01', 'waiting', ?, ?)`,
		now, now)

	if _, err := db.Exec(
		`INSERT INTO devices (mac, state, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:02', 'hacked', ?, ?)`,
		now, now,
	); err == nil {
		t.Fatal("devices.state CHECK accepted 'hacked' — constraint is missing")
	}
}

// TestZonePolicyEnumEnforced covers the second documented CHECK enum
// (vpn_policy: off/preferred/required, DD-08).
func TestZonePolicyEnumEnforced(t *testing.T) {
	db := openTestDB(t)

	mustExec(t, db,
		`INSERT INTO zones (id, name, subnet, vpn_policy) VALUES (2, 'pos', '10.20.2.0/24', 'required')`)

	if _, err := db.Exec(
		`INSERT INTO zones (id, name, subnet, vpn_policy) VALUES (3, 'bad', '10.20.9.0/24', 'maybe')`,
	); err == nil {
		t.Fatal("zones.vpn_policy CHECK accepted 'maybe' — constraint is missing")
	}
}

// TestZoneIDRangeEnforced: zones.id is bounded 1..16 by CHECK.
func TestZoneIDRangeEnforced(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(
		`INSERT INTO zones (id, name, subnet) VALUES (17, 'overflow', '10.20.17.0/24')`,
	); err == nil {
		t.Fatal("zones.id CHECK accepted 17 (max is 16)")
	}
	if _, err := db.Exec(
		`INSERT INTO zones (id, name, subnet) VALUES (0, 'zero', '10.20.0.0/24')`,
	); err == nil {
		t.Fatal("zones.id CHECK accepted 0 (min is 1)")
	}
}

// TestForeignKeysEnforced verifies the DSN's _pragma=foreign_keys(ON) is
// really active: modernc.org/sqlite defaults FKs OFF, which would make
// every REFERENCES clause in the schema decorative.
func TestForeignKeysEnforced(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(
		`INSERT INTO devices (mac, state, zone_id, first_seen, last_seen)
		 VALUES ('aa:bb:cc:dd:ee:03', 'approved', 999, 0, 0)`,
	); err == nil {
		t.Fatal("FK to zones accepted a nonexistent zone_id — foreign_keys pragma is OFF")
	}
}

// TestGuestSessionsCompositePK: spec §8 keys sessions on (mac,
// started_at) — a device may have many sessions over time, but only one
// per start instant.
func TestGuestSessionsCompositePK(t *testing.T) {
	db := openTestDB(t)

	mustExec(t, db,
		`INSERT INTO guest_sessions (mac, started_at, expires_at) VALUES ('aa:bb:cc:dd:ee:04', 100, 700)`)
	if _, err := db.Exec(
		`INSERT INTO guest_sessions (mac, started_at, expires_at) VALUES ('aa:bb:cc:dd:ee:04', 100, 900)`,
	); err == nil {
		t.Fatal("guest_sessions accepted a duplicate (mac, started_at) — PK is wrong")
	}
	// A later session for the same MAC is fine.
	mustExec(t, db,
		`INSERT INTO guest_sessions (mac, started_at, expires_at) VALUES ('aa:bb:cc:dd:ee:04', 800, 1500)`)
}

// TestPartialUniqueIndexOnUnsynced: the partial index
// idx_guest_unsynced only covers synced = 0 rows; multiple synced rows
// must be allowed.
func TestPartialUniqueIndexOnUnsynced(t *testing.T) {
	db := openTestDB(t)

	// Two sessions, both already synced: allowed.
	mustExec(t, db,
		`INSERT INTO guest_sessions (mac, started_at, expires_at, synced) VALUES ('aa:bb:cc:dd:ee:05', 100, 700, 1)`)
	mustExec(t, db,
		`INSERT INTO guest_sessions (mac, started_at, expires_at, synced) VALUES ('aa:bb:cc:dd:ee:05', 800, 1500, 1)`)
}

// TestVouchersUniqueCode pins the voucher code path (portal M3 will rely
// on it): duplicate codes must be rejected.
func TestVouchersUniqueCode(t *testing.T) {
	db := openTestDB(t)

	mustExec(t, db,
		`INSERT INTO vouchers (code, duration_s, created_at) VALUES ('KAFE-001', 3600, 0)`)
	if _, err := db.Exec(
		`INSERT INTO vouchers (code, duration_s, created_at) VALUES ('KAFE-001', 7200, 0)`,
	); err == nil {
		t.Fatal("vouchers accepted a duplicate code — PRIMARY KEY is wrong")
	}
}

// TestSsidFKToZones: ssids.zone_id REFERENCES zones(id), exercised with a
// valid row so we know the happy path of the FK wiring works too.
func TestSsidFKToZones(t *testing.T) {
	db := openTestDB(t)

	mustExec(t, db, `INSERT INTO zones (id, name, subnet) VALUES (1, 'staff', '10.20.1.0/24')`)
	mustExec(t, db,
		`INSERT INTO ssids (id, name, zone_id, security) VALUES (1, 'KotaCloud-Staff', 1, 'wpa2')`)

	if _, err := db.Exec(
		`INSERT INTO ssids (id, name, zone_id, security) VALUES (2, 'Orphan', 42, 'wpa2')`,
	); err == nil {
		t.Fatal("ssids accepted a zone_id with no matching zone")
	}
}
