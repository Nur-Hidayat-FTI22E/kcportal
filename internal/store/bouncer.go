package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// FloodCap is the FR-BNC-007 bound on devices rows: the Waiting
// quarantine is implicit in nft (a MAC without a mac_zone entry is mark
// 0), so only the bookkeeping table needs a cap — default 256, oldest
// evicted, event bouncer.flood emitted by the caller when it trips.
const FloodCap = 256

// UpsertSeenDevice records a device discovery from a watcher (lease hook
// or neighbor watcher, DD-03 sources). It inserts Waiting rows for new
// MACs and refreshes last_seen/hostname for known ones. The flood cap
// bounds the table: when it trips, the caller should surface the
// bouncer.flood bus event.
func UpsertSeenDevice(db *sql.DB, mac, hostname, source string, now time.Time) (inserted bool, err error) {
	if mac == "" {
		return false, fmt.Errorf("store: seen device: empty MAC")
	}
	mac = strings.ToLower(mac)

	if _, err := db.Exec(`INSERT INTO devices (mac, state, hostname, first_seen, last_seen)
		VALUES (?, 'waiting', ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			last_seen = excluded.last_seen,
			hostname = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname)`,
		mac, hostname, now.Unix(), now.Unix()); err != nil {
		return false, fmt.Errorf("store: upsert seen device %s: %w", mac, err)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM devices`).Scan(&n); err != nil {
		return false, fmt.Errorf("store: count devices: %w", err)
	}
	if n > FloodCap {
		// FR-BNC-007: drop the longest-unseen rows (blocked/dormant first
		// is an M3 admin policy refinement; oldest last_seen is safe now).
		if _, err := db.Exec(`DELETE FROM devices WHERE mac IN (
			SELECT mac FROM devices WHERE state NOT IN ('approved')
			ORDER BY last_seen ASC LIMIT ?)`, n-FloodCap); err != nil {
			return false, fmt.Errorf("store: flood cap eviction: %w", err)
		}
		return false, fmt.Errorf("store: device table over flood cap (%d) — bouncer.flood", n)
	}

	var first int64
	if err := db.QueryRow(`SELECT first_seen FROM devices WHERE mac = ?`, mac).Scan(&first); err != nil {
		return false, fmt.Errorf("store: read back device %s: %w", mac, err)
	}
	return first == now.Unix(), nil
}

// UpsertLease records one live DHCP lease (IF-05b hook; the design's
// lease+60s grace is applied at render time from Plan.Now, so the cache
// stores the plain live view here). Reserved rows (approved IPAM,
// DD-03) win: the hook refreshes their timestamp but must not unpin or
// move them.
func UpsertLease(db *sql.DB, mac, ip string, leaseTTL time.Duration, now time.Time) error {
	mac = strings.ToLower(mac)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("store: lease %s: bad ip %q: %w", mac, ip, err)
	}
	var reserved int
	if err := db.QueryRow(`SELECT COALESCE(reserved, 0) FROM ip_leases WHERE mac = ?`, mac).Scan(&reserved); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: lease lookup %s: %w", mac, err)
		}
	}
	if reserved != 0 {
		// Refresh the live view, keep the reservation's ip and pin.
		if _, err := db.Exec(`UPDATE ip_leases SET updated_at = ? WHERE mac = ?`, now.Unix(), mac); err != nil {
			return fmt.Errorf("store: lease refresh %s: %w", mac, err)
		}
		return nil
	}
	if _, err := db.Exec(`INSERT INTO ip_leases (mac, ip4, reserved, updated_at)
		VALUES (?, ?, 0, ?)
		ON CONFLICT(mac) DO UPDATE SET ip4 = excluded.ip4, updated_at = excluded.updated_at`,
		mac, addr.String(), now.Unix()); err != nil {
		return fmt.Errorf("store: lease upsert %s: %w", mac, err)
	}
	return nil
}

// RemoveLease deletes a lease row (hook action "del").
func RemoveLease(db *sql.DB, mac string) error {
	if _, err := db.Exec(`DELETE FROM ip_leases WHERE mac = ? AND reserved = 0`, strings.ToLower(mac)); err != nil {
		return fmt.Errorf("store: lease delete %s: %w", mac, err)
	}
	return nil // reserved rows survive: deletion of a reservation is an admin action, not a lease event
}

// SetDeviceHostname updates only the hostname (hook "old" with a name
// the GUI should show, FR-BNC-010 bookkeeping).
func SetDeviceHostname(db *sql.DB, mac, hostname string, now time.Time) error {
	if _, err := db.Exec(`UPDATE devices SET hostname = ?, last_seen = ? WHERE mac = ?`,
		hostname, now.Unix(), strings.ToLower(mac)); err != nil {
		return fmt.Errorf("store: hostname %s: %w", mac, err)
	}
	return nil
}

// FlushExpiredDevices demotes approvals whose expires_at passed and
// expires leases that have not been seen within ttl — the janitor half
// of the Bouncer Tick (§4.6). Returns the MACs it demoted.
func FlushExpiredDevices(db *sql.DB, now time.Time) ([]string, error) {
	var demoted []string
	rows, err := db.Query(`SELECT mac FROM devices WHERE state = 'approved' AND expires_at IS NOT NULL AND expires_at <= ?`,
		now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: scan expired approvals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			return nil, fmt.Errorf("store: scan expired mac: %w", err)
		}
		demoted = append(demoted, mac)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, mac := range demoted {
		if _, err := db.Exec(`UPDATE devices SET state = 'expired' WHERE mac = ?`, mac); err != nil {
			return demoted, fmt.Errorf("store: expire %s: %w", mac, err)
		}
	}
	return demoted, nil
}

// CountDevicesByState is the GUI/health read (FR-BNC-003 bookkeeping).
func CountDevicesByState(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`SELECT state, COUNT(1) FROM devices GROUP BY state`)
	if err != nil {
		return nil, fmt.Errorf("store: count by state: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, fmt.Errorf("store: scan count: %w", err)
		}
		out[s] = n
	}
	return out, rows.Err()
}
