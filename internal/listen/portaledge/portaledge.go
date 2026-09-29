// Package portaledge serves the captive guest portal (§5, FR-CPT-001):
// the ONLY path that grants internet access. The nft DNAT rules put
// every unauthenticated guest's :80 here (10.20.3.1:8080); the page
// identifies the client by SOURCE IP → MAC through IF-01 (DD-10 — the
// kernel neighbor table is the identity oracle; no header or form field
// is ever trusted), shows the consent form (§5.3 FR-CPT-002), and opens
// the session through the state actor (PD-3), which renders
// authed_guests on the next reconcile.
//
// Consent model: terms acceptance is REQUIRED; marketing consent is
// optional and, when given, only the pseudonymized record (DD-11
// client_ref, §6.12) may later leave the unit — never the MAC.
package portaledge

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/netctl"
	"kotacloud-portal/internal/portal"
	"kotacloud-portal/internal/store"
)

//go:embed tmpl/*.html
var tmplFS embed.FS

// Config tunes the portal-edge listener.
type Config struct {
	Addr        string        // 10.20.3.1:8080
	GuestBridge string        // br-guest — identity resolution interface
	TTL         time.Duration // default session length
	TermsHTML   string        // optional custom terms paragraph
}

// Server is the portal-edge HTTP listener (§2.4 listener table).
type Server struct {
	Cfg    Config
	DB     *sql.DB       // read-only here; writes ride the actor
	Ctl    netctl.NetCtl // IF-01: identity + kernel authorization
	Actor  *core.Actor   // consent/session/voucher writes (PD-3)
	Portal *portal.Service
	Log    *slog.Logger
	srv    *http.Server

	mu        sync.Mutex
	boundAddr string
}

// New builds the portal-edge server.
func New(cfg Config, db *sql.DB, ctl netctl.NetCtl, actor *core.Actor, ps *portal.Service, log *slog.Logger) *Server {
	if cfg.Addr == "" {
		cfg.Addr = "10.20.3.1:8080"
	}
	if cfg.GuestBridge == "" {
		cfg.GuestBridge = "br-guest"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = portal.DefaultSessionTTL
	}
	s := &Server{Cfg: cfg, DB: db, Ctl: ctl, Actor: actor, Portal: ps, Log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("POST /{$}", s.handleConsent)
	mux.HandleFunc("GET /state", s.handleState)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// OS captive probes land on paths like /generate_204 (Android),
	// /hotspot-detect.html (Apple), /ncsi.txt (Windows), /connecttest.txt
	// (old Windows). Any non-expected answer makes the OS open its
	// captive-portal login window — we redirect to the consent page so
	// the phone shows OUR form instead of a bare error (§5 FR-CPT-003:
	// the portal must pop up without the guest typing anything).
	mux.HandleFunc("/", s.handleProbe)
	s.srv = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s
}

// handleProbe redirects every OS captive probe (and any stray GET the
// DNAT pushed here) to the consent page.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

// freebindListenConfig mirrors waitinghttp (§2.4: these listeners bind
// addresses reconcile creates later, so the bind must tolerate a missing
// local address).
func freebindListenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
}

// Run serves until ctx is cancelled (supervisor task shape).
func (s *Server) Run(ctx context.Context) error {
	ln, err := freebindListenConfig().Listen(ctx, "tcp", s.Cfg.Addr)
	if err != nil {
		return fmt.Errorf("portaledge: listen %s: %w", s.Cfg.Addr, err)
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()
	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	s.Log.Info("portal-edge listening", "addr", s.boundAddr)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

// ServeAddr reports the bound address (tests bind ":0").
func (s *Server) ServeAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}

// clientIP extracts the source IP — the ONLY identity input (DD-10).
func (s *Server) clientIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("portaledge: bad client addr %q", host)
	}
	return addr.Unmap(), nil
}

// identify resolves src IP → MAC via the kernel neighbor table and
// cross-checks the nft mac_ip4 binding (SEC-012). Neighbor is the
// authoritative source per DD-10; a lagging binding is logged softly —
// the Bouncer's hard spoof gate lands in M4.
func (s *Server) identify(r *http.Request) (string, error) {
	ip, err := s.clientIP(r)
	if err != nil {
		return "", err
	}
	mac, err := s.Ctl.LookupNeighbor(s.Cfg.GuestBridge, ip)
	if err != nil {
		return "", fail(http.StatusForbidden, "identitas klien tidak ditemukan — hubungkan ulang Wi-Fi")
	}
	if !s.Ctl.Bound(mac, ip) {
		s.Log.Warn("neighbor/binding mismatch (soft) — neighbor wins (DD-10)", "ip", ip, "mac", mac)
	}
	return strings.ToLower(mac.String()), nil
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

func fail(status int, msg string) error { return &apiError{status: status, message: msg} }

// handleState is the 3 s poll endpoint: authorization status only.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	mac, err := s.identify(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	view, err := portal.View(s.DB, mac, time.Now())
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mac":        view.MAC,
		"authorized": view.Authorized,
		"expires_at": view.ExpiresAt,
		"state":      view.State,
	})
}

// handleHome renders the captive page (consent form / status).
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	mac, err := s.identify(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	view, err := portal.View(s.DB, mac, time.Now())
	if err != nil {
		writeErr(w, err)
		return
	}
	tpl, terr := template.ParseFS(tmplFS, "tmpl/portal.html")
	if terr != nil {
		writeErr(w, terr)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tpl.Execute(w, map[string]any{
		"MAC":        view.MAC,
		"Authorized": view.Authorized,
		"ExpiresAt":  view.ExpiresAt.Format("15:04"),
		"State":      view.State,
		"Terms":      s.Cfg.TermsHTML,
	})
}

// handleConsent opens the session: terms REQUIRED, marketing optional,
// voucher optional. The voucher is consumed INSIDE the actor step (same
// transaction discipline as the session row): an exhausted code can
// never open a session, and two racing redemptions of the last use
// cannot both win (store.RedeemVoucher guards used < max_uses).
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeErr(w, fail(http.StatusBadRequest, "form tidak valid"))
		return
	}
	mac, err := s.identify(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("terms")), []byte("yes")) != 1 {
		writeErr(w, fail(http.StatusBadRequest, "persetujuan syarat & ketentuan wajib"))
		return
	}
	marketing := r.PostFormValue("marketing") == "yes"
	voucher := strings.ToUpper(strings.TrimSpace(r.PostFormValue("voucher")))

	payload := map[string]string{}
	tenantID := ""
	if marketing {
		// Only typed, consented fields are recorded (FR-CPT-002/006).
		for _, k := range []string{"name", "contact"} {
			if v := strings.TrimSpace(r.PostFormValue(k)); v != "" {
				payload[k] = v
			}
		}
		tenantID = "marketing"
	}
	if voucher != "" {
		tenantID = "voucher"
	}

	sid, err := portal.SessionID()
	if err != nil {
		writeErr(w, err)
		return
	}
	cmd := core.AuthorizeGuest{
		MAC:       mac,
		TTL:       s.Cfg.TTL,
		SessionID: sid,
		TenantID:  tenantID,
		Marketing: marketing && len(payload) > 0,
		Payload:   portal.EncodePayload(payload),
		Terms:     s.Portal.TermsVersion,
		Lang:      "id",
		Voucher:   voucher,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := s.Actor.Do(ctx, cmd)
	if res.Err != nil {
		s.Log.Warn("portal authorize failed", "mac", mac, "err", res.Err)
		msg := "gagal membuka sesi — coba lagi"
		if errors.Is(res.Err, store.ErrNotFound) {
			msg = "voucher tidak valid"
		}
		writeErr(w, fail(http.StatusConflict, msg))
		return
	}
	s.Log.Info("guest session opened", "mac", mac, "session", sid,
		"marketing", cmd.Marketing, "voucher", voucher != "")
	// Redirect back: the browser now shows the authorized state via the
	// /state poll (and the DNAT no longer matches — authed_guests).
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	msg := "kesalahan internal"
	var ae *apiError
	if errors.As(err, &ae) {
		status = ae.status
		msg = ae.message
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`+"\n", msg)
}
