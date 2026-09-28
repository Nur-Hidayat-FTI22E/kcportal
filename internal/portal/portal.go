// Package portal implements MOD-PORTAL's domain logic (§5, §6.12): the
// captive guest portal is the ONLY path that grants internet access
// (FR-CPT-001) and its identity model is deliberately minimal. The
// client's MAC comes from the kernel neighbor table via IF-01 (DD-10 —
// never from a header or a form field); authorization is a guest
// session row plus the authed_guests nft set, both written through the
// state actor (PD-3).
//
// The consent gates (§5.3 FR-CPT-002): before access is granted the
// guest accepts the terms, and only with marketing consent may their
// data leave the unit. The guest_sessions payload column carries
// exactly what was consented; DD-11 means the MAC itself never leaves —
// only the HMAC pseudonym (client_ref) does (sync to kcp-server lands
// with M5's portal.sync worker; here we only mint the pseudonym).
package portal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultSessionTTL mirrors app.yaml's portal.session_ttl_minutes
// default (60 min); cmd/kcportald passes the configured value.
const DefaultSessionTTL = 60 * time.Minute

// ErrNotFound is returned when a voucher (or other lookup) does not
// exist or is no longer redeemable — intentionally indistinct so the
// HTTP layer can map everything to a single 400/404 without leaking
// which (SEC posture for public-facing endpoints).
var ErrNotFound = errors.New("portal: not found")

// Grant is what portal-edge sends to the state actor to open a guest
// session. It is the consent record + kernel authorization in one
// decision, executed by the reconcile Handler (PD-3 single writer):
// guest_sessions row, devices bookkeeping, and the authed_guests set
// all change in one handled command.
type Grant struct {
	MAC       string
	TenantID  string
	Marketing bool
	// Payload is stored only when Marketing is true (FR-CPT-002):
	// exactly the fields the guest consented to share.
	Payload map[string]string
	// Voucher redeem path: non-empty Code consumes a voucher and its
	// duration replaces the default TTL.
	VoucherCode string
}

// Service is the portal domain surface. Kernel effects (authed_guests)
// ride netctl's broker → the state actor; the session-row write lives
// in the reconcile handler too. Everything here is therefore called
// with the DB from main and never mutates the kernel directly.
type Service struct {
	// MarketingKey seeds the tenant pseudonym (DD-11): client_ref =
	// hex(HMAC-SHA256(key, mac)). Lives in state.db settings; empty key
	// disables marketing sync entirely (client_ref == "").
	MarketingKey string
	TermsVersion string

	Now func() time.Time
}

// New builds a Service.
func New(marketingKey string) *Service {
	return &Service{
		MarketingKey: marketingKey,
		TermsVersion: "2026-09",
		Now:          time.Now,
	}
}

// ClientRef derives the tenant pseudonym (DD-11): hex(HMAC-SHA256(key,
// mac)). Raw MACs never leave the unit even with marketing consent.
func (s *Service) ClientRef(mac string) string {
	if s.MarketingKey == "" {
		return ""
	}
	key, err := hex.DecodeString(s.MarketingKey)
	if err != nil || len(key) == 0 {
		// Key is configured as free-form text; hash it to key material
		// so any settings value works deterministically.
		d := sha256.Sum256([]byte(s.MarketingKey))
		key = d[:]
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strings.ToLower(mac)))
	return hex.EncodeToString(m.Sum(nil))
}

// SessionID mints an opaque per-session identifier (§8 session_id):
// random, not derivable from the MAC.
func SessionID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("portal: session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// EncodePayload renders the consent payload deterministically (sorted
// k=v pairs) — the same bytes always produce the same payload column
// value, keeping golden tests and hash-chained audit rows stable.
func EncodePayload(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		clean := func(v string) string {
			return strings.NewReplacer("=", "", ";", "", "\n", "").Replace(v)
		}
		parts = append(parts, clean(k)+"="+clean(m[k]))
	}
	return strings.Join(parts, ";")
}

// ClientView is the read model the portal page polls and the admin API
// shows for one guest MAC.
type ClientView struct {
	MAC        string
	IP         string
	State      string // device state: waiting | approved | blocked | expired | dormant
	Hostname   string
	Zone       string
	Authorized bool
	ExpiresAt  time.Time
	TTL        time.Duration
	Marketing  bool // consent recorded for the open session
}

// View assembles the read model from state.db (read-only — reads are
// allowed off the actor goroutine; PD-3 governs writes only).
func View(db *sql.DB, mac string, now time.Time) (ClientView, error) {
	v := ClientView{MAC: mac, State: "waiting"}
	var (
		hostname, zone   sql.NullString
		started, expires sql.NullInt64
		payload          sql.NullString
		closed           sql.NullInt64
	)
	err := db.QueryRow(`SELECT COALESCE(d.state,'waiting'), COALESCE(d.hostname,''), COALESCE(z.name,''),
			COALESCE(gs.started_at,0), COALESCE(gs.expires_at,0), COALESCE(gs.payload,''), COALESCE(gs.closed_at,0)
		FROM devices d
		LEFT JOIN zones z ON z.id = d.zone_id
		LEFT JOIN guest_sessions gs ON gs.mac = d.mac AND gs.closed_at IS NULL
		WHERE d.mac = ?
		ORDER BY gs.started_at DESC`, mac).Scan(
		&v.State, &hostname, &zone, &started, &expires, &payload, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil // unknown MAC = still waiting; hook will upsert on first lease
	}
	if err != nil {
		return v, fmt.Errorf("portal: view %s: %w", mac, err)
	}
	v.Hostname = hostname.String
	v.Zone = zone.String
	if expires.Valid && closed.Int64 == 0 && time.Unix(expires.Int64, 0).After(now) {
		v.Authorized = true
		v.ExpiresAt = time.Unix(expires.Int64, 0)
		v.TTL = v.ExpiresAt.Sub(now)
		v.Marketing = payload.String != ""
	}
	return v, nil
}
