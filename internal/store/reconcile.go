package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrNotFound is returned by getters that found no row.
var ErrNotFound = errors.New("store: not found") // EnsureSeedZones inserts the default Café zones (config) into a fresh
// state.db. Idempotent: existing zones are updated in place, so a config
// change to name/subnet/mark propagates on the next boot. Zones with
// ID <= 0 are skipped: the schema bounds ids to 1..16 and the Waiting
// zone (§2.4 mark 0x00) is virtual — it is the devices.state column, not
// a row. Seeding is a boot-time concern, NOT a state mutation — the
// Actor never writes zones.
func EnsureSeedZones(db *sql.DB, zones []SeedZone) error {
	for _, z := range zones {
		if z.ID <= 0 {
			continue
		}
		if _, err := db.Exec(`INSERT INTO zones (id, name, subnet, internet)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET name = excluded.name, subnet = excluded.subnet, internet = excluded.internet`,
			z.ID, z.Name, z.Subnet, z.Internet); err != nil {
			return fmt.Errorf("store: seed zone %d: %w", z.ID, err)
		}
	}
	return nil
}

// SeedZone is one zone definition the boot path seeds into state.db.
type SeedZone struct {
	ID       int
	Name     string
	Subnet   string
	Internet bool
}

// LoadPlan reads everything the reconciler needs to render the nftables
// ruleset. It is the state.db → Plan half of the M1 wiring: pure reads,
// no mutation, safe to call from the actor goroutine (the single writer
// principle, PD-3, still holds — writes only ever happen inside the
// Handler commands).
//
// now is the caller's clock: expiry filtering must use the SAME time the
// mutations were stamped with, or a test/controlled clock makes fresh
// sessions look expired. Production passes time.Now().
func LoadPlan(db *sql.DB, now time.Time) (*Plan, error) {
	zones, err := loadZones(db)
	if err != nil {
		return nil, err
	}
	devices, err := loadApprovedDevices(db)
	if err != nil {
		return nil, err
	}
	guests, err := loadActiveGuests(db, now)
	if err != nil {
		return nil, err
	}
	bindings, err := loadBindings(db)
	if err != nil {
		return nil, err
	}
	return &Plan{
		Zones:    zones,
		Devices:  devices,
		Guests:   guests,
		Bindings: bindings,
	}, nil
}

// Plan is the reconciler-level snapshot handed to nft.Plan by the
// Handler; it carries store-native types so the nft package stays free
// of store imports.
type Plan struct {
	Zones    []Zone
	Devices  []Device
	Guests   []GuestSession
	Bindings []Lease
}

// Zone mirrors the zones row (§8), including the policy columns the
// state actor owns (PutZonePolicy writes them; render reads them).
type Zone struct {
	ID       int
	Name     string
	Subnet   string
	Mark     uint32
	Internet bool
	VPN      string     // vpn_policy: off | preferred | required
	LANAllow []LANAllow // parsed from the lan_allow JSON column
}

// LANAllow is one inter-zone exception (store-level shape).
type LANAllow struct {
	DstIP string `json:"dst_ip"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// Device is an approved device that must appear in the mac_zone map.
type Device struct {
	MAC     string
	ZoneID  int
	State   string
	Expires *time.Time // nil = no expiry
}

// GuestSession is an open guest session for authed_guests.
type GuestSession struct {
	MAC       string
	ExpiresAt time.Time
}

// Lease is an ip_leases row: the anti-spoof mac_ip4/mac_ip6 entries.
type Lease struct {
	MAC      string
	IP       netip.Addr
	Reserved bool
	Updated  time.Time
	// Expires is nil for reservations (they persist until revoked).
	Expires *time.Time
}

func loadZones(db *sql.DB) ([]Zone, error) {
	rows, err := db.Query(`SELECT id, name, subnet, internet, vpn_policy, lan_allow FROM zones ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: load zones: %w", err)
	}
	defer rows.Close()
	var out []Zone
	for rows.Next() {
		var z Zone
		var internet int
		var lanAllow string
		if err := rows.Scan(&z.ID, &z.Name, &z.Subnet, &internet, &z.VPN, &lanAllow); err != nil {
			return nil, fmt.Errorf("store: scan zone: %w", err)
		}
		z.Internet = internet != 0
		if lanAllow != "" && lanAllow != "[]" {
			if err := json.Unmarshal([]byte(lanAllow), &z.LANAllow); err != nil {
				return nil, fmt.Errorf("store: zone %d lan_allow: %w", z.ID, err)
			}
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// PutZonePolicy writes the policy columns of one zone (core.PutZonePolicy
// handler; the M3 REST admin calls the same path). LANAllow rules are
// stored as the JSON the §8 schema's lan_allow column wants.
func PutZonePolicy(db *sql.DB, zoneID int, internet bool, vpnRequired bool, allows []LANAllow, actor string, now time.Time) error {
	vpn := "off"
	if vpnRequired {
		vpn = "required"
	}
	jsonAllows, err := json.Marshal(allows)
	if err != nil {
		return fmt.Errorf("store: zone %d policy: %w", zoneID, err)
	}
	res, err := db.Exec(`UPDATE zones SET internet = ?, vpn_policy = ?, lan_allow = ? WHERE id = ?`,
		boolToInt(internet), vpn, string(jsonAllows), zoneID)
	if err != nil {
		return fmt.Errorf("store: zone %d policy: %w", zoneID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: zone %d policy: %w", zoneID, ErrNotFound)
	}
	return RecordAudit(db, actor, "zone.policy", fmt.Sprintf("zone:%d", zoneID), string(jsonAllows), now)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func loadApprovedDevices(db *sql.DB) ([]Device, error) {
	rows, err := db.Query(`SELECT mac, zone_id, state, expires_at FROM devices WHERE state = 'approved'`)
	if err != nil {
		return nil, fmt.Errorf("store: load approved devices: %w", err)
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var zoneID sql.NullInt64
		var expires sql.NullInt64
		if err := rows.Scan(&d.MAC, &zoneID, &d.State, &expires); err != nil {
			return nil, fmt.Errorf("store: scan device: %w", err)
		}
		if !zoneID.Valid {
			return nil, fmt.Errorf("store: device %s is approved but has no zone_id", d.MAC)
		}
		d.ZoneID = int(zoneID.Int64)
		if expires.Valid {
			t := time.Unix(expires.Int64, 0)
			d.Expires = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func loadActiveGuests(db *sql.DB, now time.Time) ([]GuestSession, error) {
	rows, err := db.Query(`SELECT mac, expires_at FROM guest_sessions
		WHERE closed_at IS NULL AND expires_at > ?`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: load active guest sessions: %w", err)
	}
	defer rows.Close()
	var out []GuestSession
	for rows.Next() {
		var g GuestSession
		var expires int64
		if err := rows.Scan(&g.MAC, &expires); err != nil {
			return nil, fmt.Errorf("store: scan guest session: %w", err)
		}
		g.ExpiresAt = time.Unix(expires, 0)
		out = append(out, g)
	}
	return out, rows.Err()
}

func loadBindings(db *sql.DB) ([]Lease, error) {
	rows, err := db.Query(`SELECT mac, ip4, reserved, updated_at FROM ip_leases WHERE ip4 IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("store: load ip leases: %w", err)
	}
	defer rows.Close()
	var out []Lease
	for rows.Next() {
		var l Lease
		var ip string
		var reserved int
		var updated int64
		if err := rows.Scan(&l.MAC, &ip, &reserved, &updated); err != nil {
			return nil, fmt.Errorf("store: scan lease: %w", err)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("store: ip_leases row %s has invalid ip4 %q: %w", l.MAC, ip, err)
		}
		l.IP = addr
		l.Reserved = reserved != 0
		l.Updated = time.Unix(updated, 0)
		out = append(out, l)
	}
	return out, rows.Err()
}

// --- single-writer mutations (called only from the Actor's Handler) ---

// ApproveDevice moves a device out of Waiting into its zone (FR-BNC-008).
// Upsert: re-approving an existing MAC re-zones it instead of failing.
func ApproveDevice(db *sql.DB, mac string, zoneID int, note string, actor string, now time.Time) error {
	// The zone must exist: FK is only checked when foreign_keys is on for
	// THIS connection, and the reconciler may run before any zone row
	// exists after a manual db wipe.
	var one int
	if err := db.QueryRow(`SELECT COUNT(1) FROM zones WHERE id = ?`, zoneID).Scan(&one); err != nil {
		return fmt.Errorf("store: check zone %d: %w", zoneID, err)
	}
	if one == 0 {
		return fmt.Errorf("store: approve device %s: zone %d does not exist (zones not seeded?)", mac, zoneID)
	}

	if _, err := db.Exec(`INSERT INTO devices (mac, state, zone_id, first_seen, last_seen, approved_by, approved_at)
		VALUES (?, 'approved', ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			state = 'approved', zone_id = excluded.zone_id,
			last_seen = excluded.last_seen, approved_by = excluded.approved_by, approved_at = excluded.approved_at`,
		mac, zoneID, now.Unix(), now.Unix(), actor, now.Unix()); err != nil {
		return fmt.Errorf("store: approve device %s: %w", mac, err)
	}
	return RecordAudit(db, actor, "device.approve", mac, note, now)
}

// BlockDevice flips a device to 'blocked' (admin moderation).
func BlockDevice(db *sql.DB, mac, actor string, now time.Time) error {
	res, err := db.Exec(`UPDATE devices SET state = 'blocked', last_seen = ? WHERE mac = ?`, now.Unix(), mac)
	if err != nil {
		return fmt.Errorf("store: block device %s: %w", mac, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: block device %s: %w", mac, ErrNotFound)
	}
	return RecordAudit(db, actor, "device.block", mac, "", now)
}

// ReserveLease pins mac→ip in ip_leases (DD-03 IPAM; reserved rows never
// expire and always render into the anti-spoof sets).
func ReserveLease(db *sql.DB, mac, ip string, now time.Time) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("store: reserve lease %s -> %s: %w", mac, ip, err)
	}
	if _, err := db.Exec(`INSERT INTO ip_leases (mac, ip4, reserved, updated_at)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(mac) DO UPDATE SET ip4 = excluded.ip4, reserved = 1, updated_at = excluded.updated_at`,
		mac, addr.String(), now.Unix()); err != nil {
		return fmt.Errorf("store: reserve lease %s: %w", mac, err)
	}
	return nil
}

// StartGuestSession opens a guest session; authed_guests entries are
// derived from it on the next Plan build (§8, portal-edge IF-01).
func StartGuestSession(db *sql.DB, mac string, ttl time.Duration, now time.Time) error {
	if ttl <= 0 {
		return fmt.Errorf("store: guest session for %s: ttl must be positive", mac)
	}
	if _, err := db.Exec(`INSERT INTO guest_sessions (mac, started_at, expires_at)
		VALUES (?, ?, ?)`, mac, now.Unix(), now.Add(ttl).Unix()); err != nil {
		return fmt.Errorf("store: start guest session %s: %w", mac, err)
	}
	return nil
}

// SessionMeta carries the portal's consent record (§8 delta columns):
// written together with the session row inside one handler step so the
// audit trail never shows an authorized session without its consent.
type SessionMeta struct {
	MAC        string
	SessionID  string
	TenantID   string
	Marketing  bool
	Payload    string // empty unless Marketing; portal.EncodePayload output
	Terms      string
	Lang       string
	Expiration time.Time
}

// StartGuestSessionWithMeta opens a session with the portal's consent
// metadata. session_id is generated by the caller (portal.SessionID —
// keep crypto/rand out of this package).
func StartGuestSessionWithMeta(db *sql.DB, m SessionMeta, now time.Time) error {
	ttl := m.Expiration.Sub(now)
	if ttl <= 0 {
		return fmt.Errorf("store: guest session for %s: expiration must be in the future", m.MAC)
	}
	marketing := 0
	if m.Marketing {
		marketing = 1
	}
	_, err := db.Exec(`INSERT INTO guest_sessions
		(mac, started_at, expires_at, session_id, tenant_id, consent_marketing, payload, terms_version, lang)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.MAC, now.Unix(), m.Expiration.Unix(), nullIfEmpty(m.SessionID), nullIfEmpty(m.TenantID),
		marketing, nullIfEmpty(m.Payload), nullIfEmpty(m.Terms), nullIfEmpty(m.Lang))
	if err != nil {
		return fmt.Errorf("store: start guest session %s: %w", m.MAC, err)
	}
	return nil
}

// RedeemVoucher consumes one use of code and returns its duration.
// Unknown/expired/exhausted all collapse to ErrNotFound (do not leak
// which to a public endpoint). The UPDATE guards max_uses atomically —
// two concurrent redemptions of the last use cannot both succeed.
func RedeemVoucher(db *sql.DB, code string, now time.Time) (time.Duration, error) {
	res, err := db.Exec(`UPDATE vouchers SET used = used + 1
		WHERE code = ? AND used < max_uses AND (expires_at IS NULL OR expires_at > ?)`,
		code, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: redeem voucher: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	var dur int64
	if err := db.QueryRow(`SELECT duration_s FROM vouchers WHERE code = ?`, code).Scan(&dur); err != nil {
		return 0, fmt.Errorf("store: read voucher %s: %w", code, err)
	}
	return time.Duration(dur) * time.Second, nil
}

// CreateVoucher inserts a batch of codes (admin API §7.2). Codes are
// caller-generated (random, uppercase charset).
func CreateVouchers(db *sql.DB, codes []string, duration time.Duration, maxUses int, expires time.Time, now time.Time) error {
	if duration <= 0 {
		return fmt.Errorf("store: vouchers: duration must be positive")
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	var exp any
	if !expires.IsZero() {
		exp = expires.Unix()
	}
	for _, code := range codes {
		if _, err := db.Exec(`INSERT INTO vouchers (code, duration_s, max_uses, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?)`, code, int64(duration/time.Second), maxUses, exp, now.Unix()); err != nil {
			return fmt.Errorf("store: create voucher %s: %w", code, err)
		}
	}
	return nil
}

// ListVouchers returns the voucher table for the admin UI (§7.2
// /portal/admin/vouchers). Empty slice, not nil, for clean JSON.
func ListVouchers(db *sql.DB) ([]Voucher, error) {
	rows, err := db.Query(`SELECT code, duration_s, max_uses, used, expires_at, created_at
		FROM vouchers ORDER BY created_at DESC, code`)
	if err != nil {
		return nil, fmt.Errorf("store: list vouchers: %w", err)
	}
	defer rows.Close()
	out := []Voucher{}
	for rows.Next() {
		var v Voucher
		var created int64
		var expNull sql.NullInt64
		if err := rows.Scan(&v.Code, &v.DurationSec, &v.MaxUses, &v.Used, &expNull, &created); err != nil {
			return nil, fmt.Errorf("store: scan voucher: %w", err)
		}
		if expNull.Valid {
			v.ExpiresAt = time.Unix(expNull.Int64, 0)
		}
		v.CreatedAt = time.Unix(created, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteVoucher removes one voucher code (admin housekeeping). It
// returns ErrNotFound when the code does not exist. Sessions already
// started from this voucher keep their own expires_at.
func DeleteVoucher(db *sql.DB, code string) error {
	res, err := db.Exec(`DELETE FROM vouchers WHERE code = ?`, code)
	if err != nil {
		return fmt.Errorf("store: delete voucher %s: %w", code, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Voucher is one vouchers row (read model).
type Voucher struct {
	Code        string
	DurationSec int64
	MaxUses     int
	Used        int
	ExpiresAt   time.Time // zero = never expires
	CreatedAt   time.Time
}

// AuditEntry is one audit_log row for the admin API (§7.2 /audit).
type AuditEntry struct {
	ID     int64
	Ts     time.Time
	Actor  string
	Action string
	Target string
	Diff   string
}

// ListAudit returns the newest audit rows (hash chain keeps them
// tamper-evident; the API exposes the chain verbatim, verification is
// a hardening task).
func ListAudit(db *sql.DB, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.Query(`SELECT id, ts, actor, action, COALESCE(target,''), COALESCE(diff,'')
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.Diff); err != nil {
			return nil, fmt.Errorf("store: scan audit: %w", err)
		}
		a.Ts = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CloseGuestSessions closes every open session for mac (portal logout /
// revocation).
func CloseGuestSessions(db *sql.DB, mac string, now time.Time) error {
	if _, err := db.Exec(`UPDATE guest_sessions SET closed_at = ? WHERE mac = ? AND closed_at IS NULL`,
		now.Unix(), mac); err != nil {
		return fmt.Errorf("store: close guest sessions %s: %w", mac, err)
	}
	return nil
}

// SetSetting upserts a key/value row (§8 settings — e.g. last applied
// ruleset hash for the drift check).
func SetSetting(db *sql.DB, key, value string) error {
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("store: set setting %s: %w", key, err)
	}
	return nil
}

// GetSetting reads a settings row; ErrNotFound when absent.
func GetSetting(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get setting %s: %w", key, err)
	}
	return v, nil
}

// recordAudit appends one hash-chained audit row (§8 audit_log: SHA-256
// chain over prev_hash; M1 keeps the chain shape, the hash function
// plugging into it is a hardening task — for now SHA-256 directly).
// RecordAudit appends one hash-chained audit row; exported so the
// settings-level mutations that bypass the actor (wan posture) leave
// the same tamper-evident trail as actor commands.
func RecordAudit(db *sql.DB, actor, action, target, diff string, now time.Time) error {
	var prev []byte
	if err := db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: read prev audit hash: %w", err)
		}
		prev = []byte("genesis") // first row anchors the chain
	}
	entry := fmt.Sprintf("%s|%d|%s|%s|%s", prev, now.Unix(), actor, action, target)
	sum := sha256.Sum256([]byte(entry))
	if _, err := db.Exec(`INSERT INTO audit_log (ts, actor, action, target, diff, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		now.Unix(), actor, action, target, diff, prev, sum[:]); err != nil {
		return fmt.Errorf("store: insert audit row: %w", err)
	}
	return nil
}
