// Package api implements the REST admin surface (§7.2): the endpoints
// web/admin (M3 GUI) and the setup wizard call. Transport is a plain
// stdlib mux bound to 127.0.0.1:8083 by cmd/kcportald — reachability is
// the mgmt plane's business (br-lan address or SSH tunnel), NOT this
// package's: it authenticates every mutation with a token and trusts
// nothing else.
//
// Endpoint map (§7.2 subset that state.db can already serve):
//
//	POST /api/v1/devices/approve      {mac, zone_id, note}
//	POST /api/v1/devices/block        {mac}
//	GET  /api/v1/devices              ?state=waiting|approved|…
//	GET  /api/v1/guests               live sessions (devices+sessions)
//	POST /api/v1/guests/revoke        {mac}   → actor RevokeGuest
//	GET  /api/v1/zones                zone rows + policy
//	PUT  /api/v1/zones/{id}/policy    → actor PutZonePolicy (risky: Admin zone rides commit-confirm)
//	GET  /api/v1/changes/pending      {pending, change_id?, deadline?}
//	POST /api/v1/changes/confirm      {change_id}
//	GET  /api/v1/audit?limit=         hash-chained rows (read-only)
//	POST /api/v1/vouchers             {count, duration_s, max_uses}
//	GET  /api/v1/vouchers
//	DELETE /api/v1/vouchers/{code}    remove one voucher (housekeeping)
//	GET  /api/v1/network/wan          posture view (setup wizard, read-only)
//	POST /api/v1/network/wan          {wan:{mode}, iface} — records intent (no kernel writes)
//
// Auth: Authorization: Bearer <token>. The token is generated on first
// boot into state.db settings (32 random bytes hex) and shown once by
// the ops CLI (`kcportald -api-token`); the GUI stores it per browser.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"kotacloud-portal/internal/api/webadmin"
	"kotacloud-portal/internal/confirm"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/portal"
	"kotacloud-portal/internal/store"
)

// Server carries the collaborators the endpoints need.
type Server struct {
	DB        *sql.DB
	Actor     *core.Actor
	Portal    *portal.Service
	Confirmer *confirm.Manager
	Log       *slog.Logger
	// Tokens holds the accepted bearer tokens (hash set semantics are
	// overkill for one admin token; string compare under atomic load).
	Token atomic.Value // string
}

// LoadToken reads the API token from settings, creating one on first
// call. Returns the plaintext token ONLY on creation (the CLI prints
// it once); later boots log nothing.
func LoadToken(db *sql.DB) (string, bool, error) {
	tok, err := store.GetSetting(db, "api_token")
	if err == nil && tok != "" {
		return tok, false, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false, fmt.Errorf("api: token generation: %w", err)
	}
	tok = hex.EncodeToString(buf)
	if err := store.SetSetting(db, "api_token", tok); err != nil {
		return "", false, err
	}
	return tok, true, nil
}

// SetToken installs the accepted bearer token.
func (s *Server) SetToken(tok string) { s.Token.Store(tok) }

// Handler builds the routed mux with auth middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/devices/approve", s.wrap(s.handleApprove))
	mux.HandleFunc("POST /api/v1/devices/block", s.wrap(s.handleBlock))
	mux.HandleFunc("GET /api/v1/devices", s.wrap(s.handleDevices))
	mux.HandleFunc("GET /api/v1/guests", s.wrap(s.handleGuests))
	mux.HandleFunc("POST /api/v1/guests/revoke", s.wrap(s.handleRevoke))
	mux.HandleFunc("GET /api/v1/zones", s.wrap(s.handleZones))
	mux.HandleFunc("PUT /api/v1/zones/{id}/policy", s.wrap(s.handleZonePolicy))
	mux.HandleFunc("GET /api/v1/changes/pending", s.wrap(s.handlePending))
	mux.HandleFunc("POST /api/v1/changes/confirm", s.wrap(s.handleConfirm))
	mux.HandleFunc("GET /api/v1/audit", s.wrap(s.handleAudit))
	mux.HandleFunc("POST /api/v1/vouchers", s.wrap(s.handleCreateVouchers))
	mux.HandleFunc("GET /api/v1/vouchers", s.wrap(s.handleListVouchers))
	mux.HandleFunc("DELETE /api/v1/vouchers/{code}", s.wrap(s.handleDeleteVoucher))
	// Setup wizard (M3, §7.2): read-only posture view + recorded WAN
	// posture. Kernel-facing reconfig stays with kcp-net-apply.sh.
	mux.HandleFunc("GET /api/v1/network/wan", s.wrap(s.HandleWanGET))
	mux.HandleFunc("POST /api/v1/network/wan", s.wrap(s.HandleWanPOST))
	// DoH shield monitoring (M3.5): live drop counters for the GUI.
	mux.HandleFunc("GET /api/v1/network/doh", s.wrap(s.HandleShieldGET))
	// The admin GUI (web/admin, compiled-in via internal/api/webadmin)
	// rides the same listener: static paths are served without the
	// bearer token (the browser must be able to load the login page
	// before any token exists — the bundle holds no secrets), while
	// everything under /api/ keeps the auth middleware.
	gui := webadmin.Handler()
	apiHandler := s.auth(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		gui.ServeHTTP(w, r)
	})
}

// --- plumbing ---

type jsonHandler func(w http.ResponseWriter, r *http.Request) (any, error)

func (s *Server) wrap(h jsonHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := h(w, r)
		if err != nil {
			var httpErr *httpError
			if errors.As(err, &httpErr) {
				writeJSON(w, httpErr.Status, map[string]string{"error": httpErr.Message})
				return
			}
			s.Log.Warn("api error", "path", r.URL.Path, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if out != nil {
			writeJSON(w, http.StatusOK, out)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type httpError struct {
	Status  int
	Message string
}

func (e *httpError) Error() string { return e.Message }

func fail(status int, msg string) error { return &httpError{Status: status, Message: msg} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := s.Token.Load().(string)
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || got == "" || got != tok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) do(r *http.Request, cmd core.Command) (core.Result, error) {
	// IF-02: every actor round-trip carries a deadline.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := s.Actor.Do(ctx, cmd)
	if res.Err != nil {
		return res, fail(http.StatusConflict, res.Err.Error())
	}
	return res, nil
}

func decode(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "bad json: "+err.Error())
	}
	return nil
}

// --- endpoints ---

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		MAC    string `json:"mac"`
		ZoneID int    `json:"zone_id"`
		Note   string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	res, err := s.do(r, core.ApproveDevice{MAC: strings.ToLower(req.MAC), ZoneID: req.ZoneID, Note: req.Note})
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "change_id": res.ChangeID, "deadline": res.Deadline}, nil
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		MAC string `json:"mac"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	// Block also revokes any live guest session (moderation must cut
	// access now, not after the session TTL).
	if _, err := s.do(r, core.RevokeGuest{MAC: strings.ToLower(req.MAC)}); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) (any, error) {
	state := r.URL.Query().Get("state")
	q := `SELECT d.mac, COALESCE(d.state,''), COALESCE(d.hostname,''), COALESCE(z.name,''),
			COALESCE(l.ip4,''), d.last_seen
		FROM devices d
		LEFT JOIN zones z ON z.id = d.zone_id
		LEFT JOIN ip_leases l ON l.mac = d.mac`
	args := []any{}
	if state != "" {
		q += ` WHERE d.state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY d.last_seen DESC LIMIT 500`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type device struct {
		MAC, State, Hostname, Zone, IP string
		LastSeen                       time.Time
	}
	out := []device{}
	for rows.Next() {
		var d device
		var last int64
		if err := rows.Scan(&d.MAC, &d.State, &d.Hostname, &d.Zone, &d.IP, &last); err != nil {
			return nil, err
		}
		d.LastSeen = time.Unix(last, 0)
		out = append(out, d)
	}
	return map[string]any{"devices": out}, rows.Err()
}

func (s *Server) handleGuests(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.DB.Query(`SELECT gs.mac, COALESCE(l.ip4,''), gs.started_at, gs.expires_at, COALESCE(gs.payload,'')
		FROM guest_sessions gs
		LEFT JOIN ip_leases l ON l.mac = gs.mac
		WHERE gs.closed_at IS NULL AND gs.expires_at > ?
		ORDER BY gs.expires_at`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type guest struct {
		MAC, IP   string
		StartedAt time.Time `json:"started_at"`
		ExpiresAt time.Time `json:"expires_at"`
		Marketing bool
	}
	out := []guest{}
	now := time.Now()
	for rows.Next() {
		var g guest
		var started, expires int64
		var payload sql.NullString
		if err := rows.Scan(&g.MAC, &g.IP, &started, &expires, &payload); err != nil {
			return nil, err
		}
		g.StartedAt = time.Unix(started, 0)
		g.ExpiresAt = time.Unix(expires, 0)
		g.Marketing = payload.Valid && payload.String != ""
		_ = now
		out = append(out, g)
	}
	return map[string]any{"guests": out}, rows.Err()
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		MAC string `json:"mac"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if _, err := s.do(r, core.RevokeGuest{MAC: strings.ToLower(req.MAC)}); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := s.DB.Query(`SELECT id, name, subnet, internet, vpn_policy, lan_allow, isolate_clients, bw_limit_kbps
		FROM zones ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type zone struct {
		ID        int
		Name      string
		Subnet    string
		Internet  bool
		VPNPolicy string
		LANAllow  string
		Isolate   bool
		BWKbps    sql.NullInt64
	}
	out := []zone{}
	for rows.Next() {
		var z zone
		var internet, isolate int
		if err := rows.Scan(&z.ID, &z.Name, &z.Subnet, &internet, &z.VPNPolicy, &z.LANAllow, &isolate, &z.BWKbps); err != nil {
			return nil, err
		}
		z.Internet = internet == 1
		z.Isolate = isolate == 1
		out = append(out, z)
	}
	return map[string]any{"zones": out}, rows.Err()
}

func (s *Server) handleZonePolicy(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		return nil, fail(http.StatusBadRequest, "bad zone id")
	}
	var req struct {
		Internet    bool `json:"internet"`
		VPNRequired bool `json:"vpn_required"`
		LANAllow    []struct {
			DstIP string `json:"dst_ip"`
			Proto string `json:"proto"`
			Port  int    `json:"port"`
		} `json:"lan_allow"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	lan := make([]core.LANAllowRule, 0, len(req.LANAllow))
	for _, a := range req.LANAllow {
		lan = append(lan, core.LANAllowRule{DstIP: a.DstIP, Proto: a.Proto, Port: a.Port})
	}
	res, err := s.do(r, core.PutZonePolicy{ZoneID: id, Internet: req.Internet, VPNRequired: req.VPNRequired, LANAllow: lan})
	if err != nil {
		return nil, err
	}
	// IF-02: risky changes (Admin zone) surface the commit-confirm
	// deadline so the GUI shows the countdown and posts /changes/confirm.
	return map[string]any{"ok": true, "change_id": res.ChangeID, "deadline": res.Deadline}, nil
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) (any, error) {
	out := map[string]any{"pending": false}
	// change_id + risk_reason ride along so the GUI can POST
	// /changes/confirm with the exact id the trial was begun under.
	if s.Confirmer != nil {
		if p, ok := s.Confirmer.Active(); ok {
			out["pending"] = true
			out["deadline"] = p.Deadline
			out["change_id"] = p.ChangeID
			out["risk_reason"] = p.RiskReason
		}
	}
	return out, nil
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		ChangeID string `json:"change_id"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.Confirmer.Confirm(req.ChangeID); err != nil {
		return nil, fail(http.StatusConflict, err.Error())
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) (any, error) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := store.ListAudit(s.DB, limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{"audit": rows}, nil
}

func (s *Server) handleCreateVouchers(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Count     int `json:"count"`
		DurationS int `json:"duration_s"`
		MaxUses   int `json:"max_uses"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Count <= 0 || req.Count > 100 {
		return nil, fail(http.StatusBadRequest, "count must be 1..100")
	}
	if req.DurationS <= 0 {
		return nil, fail(http.StatusBadRequest, "duration_s must be positive")
	}
	codes := make([]string, req.Count)
	for i := range codes {
		c, err := newVoucherCode()
		if err != nil {
			return nil, err
		}
		codes[i] = c
	}
	if err := store.CreateVouchers(s.DB, codes, time.Duration(req.DurationS)*time.Second, req.MaxUses, time.Time{}, time.Now()); err != nil {
		return nil, err
	}
	s.Log.Info("vouchers created", "count", req.Count, "duration_s", req.DurationS)
	return map[string]any{"ok": true, "codes": codes}, nil
}

func (s *Server) handleListVouchers(w http.ResponseWriter, r *http.Request) (any, error) {
	rows, err := store.ListVouchers(s.DB)
	if err != nil {
		return nil, err
	}
	return map[string]any{"vouchers": rows}, nil
}

// handleDeleteVoucher removes a single voucher code (admin housekeeping:
// cleaning up test codes or revoking an unused batch). Unknown codes
// return 404 so typos are visible in the GUI/curl output.
func (s *Server) handleDeleteVoucher(w http.ResponseWriter, r *http.Request) (any, error) {
	code := r.PathValue("code")
	if code == "" {
		return nil, fail(http.StatusBadRequest, "voucher code is required")
	}
	if err := store.DeleteVoucher(s.DB, code); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fail(http.StatusNotFound, fmt.Sprintf("voucher %q not found", code))
		}
		return nil, err
	}
	s.Log.Info("voucher deleted", "code", code)
	return map[string]any{"ok": true, "deleted": code}, nil
}

// newVoucherCode mints a human-friendly 10-char code (no 0/O/1/I/L).
func newVoucherCode() (string, error) {
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api: voucher code: %w", err)
	}
	for i, b := range buf {
		buf[i] = charset[int(b)%len(charset)]
	}
	return string(buf), nil
}
