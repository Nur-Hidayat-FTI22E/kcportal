// pos-cafe is the PoS App Pack binary (M4.3, §6.5) running rootless in
// Podman (Network=host, loopback-only listener) behind the M4.2 apps
// proxy. This builds the full PoS core on pos.db: PIN login (argon2id),
// shifts (DB-enforced single open), orders with per-day receipt
// numbering, idempotent payments that commit the receipt print job in
// the SAME transaction (FR-POS-007), admin void with audit, and the
// ESC/POS printer worker (usb|tcp).
//
// Env (IF-03): POS_ADDR (default 127.0.0.1:8444), POS_DB
// (/data/pos.db), POS_PRINTER=usb|tcp, POS_PRINTER_ADDR,
// POS_SEED_ADMIN / POS_SEED_ADMIN_PIN (first-boot admin seed).
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"kotacloud-portal/internal/pos/printer"
	posstore "kotacloud-portal/internal/pos/store"
	posweb "kotacloud-portal/internal/pos/web"
)

type app struct {
	db     *posstore.DB
	log    *slog.Logger
	secret []byte // session cookie HMAC key (random per boot: sessions die with the process, POS re-login is cheap)
}

func main() {
	addr := envOr("POS_ADDR", "127.0.0.1:8444") // loopback only — proxy is the only remote entry
	dbPath := envOr("POS_DB", "/data/pos.db")
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := posstore.Open(dbPath)
	if err != nil {
		log.Error("pos.db unavailable", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.EnsureSeedCatalog(map[string]int64{
		"Kopi Susu": 18000, "Es Teh": 8000, "Roti Bakar": 15000, "Air Mineral": 5000,
	}); err != nil {
		log.Warn("seed catalog failed", "err", err)
	}
	seedAdmin(db, log)

	a := &app{db: db, log: log, secret: newSecret()}

	// Printer worker (queue drains even when the UI is closed).
	stop := make(chan struct{})
	done := make(chan struct{})
	drv := printer.FromEnv(os.Getenv("POS_PRINTER"), os.Getenv("POS_PRINTER_ADDR"))
	go func() {
		defer close(done)
		printer.Worker(db, drv, log.Info)(stop)
	}()

	mux := http.NewServeMux()
	// The cashier UI (web/pos, compiled-in) rides the same loopback
	// listener: the SPA shell loads without a session (the login page
	// must render first), everything under /api/ enforces the session
	// per-handler via a.auth.
	spa := posweb.Handler()
	mux.Handle("/assets/", spa)
	mux.HandleFunc("GET /{$}", spa.ServeHTTP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.auth(a.handleLogout))
	mux.HandleFunc("GET /api/me", a.auth(a.handleMe))
	mux.HandleFunc("POST /api/shift/open", a.auth(a.handleShiftOpen))
	mux.HandleFunc("POST /api/shift/close", a.auth(a.handleShiftClose))
	mux.HandleFunc("GET /api/products", a.auth(a.handleProducts))
	mux.HandleFunc("POST /api/orders", a.auth(a.handleOrderCreate))
	mux.HandleFunc("POST /api/orders/{id}/items", a.auth(a.handleItemAdd))
	mux.HandleFunc("POST /api/orders/{id}/pay", a.auth(a.handlePay))
	mux.HandleFunc("POST /api/orders/{id}/void", a.auth(a.handleVoid))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		close(errCh)
	}()
	log.Info("pos-cafe listening", "addr", addr, "printer", os.Getenv("POS_PRINTER"))
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		close(stop)
		<-done
	case err := <-errCh:
		if err != nil {
			close(stop)
			log.Error("pos-cafe died", "err", err)
			os.Exit(1)
		}
	}
	log.Info("shutdown complete")
}

// --- session (HMAC-signed cookie; random per boot) ---

type session struct {
	CashierID int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Exp       int64  `json:"exp"`
}

func newSecret() []byte {
	s := make([]byte, 32)
	_, _ = rand.Read(s)
	return s
}

func (a *app) sign(v string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *app) setSession(w http.ResponseWriter, s session) {
	raw, _ := json.Marshal(s)
	val := hex.EncodeToString(raw) + "." + a.sign(string(raw))
	http.SetCookie(w, &http.Cookie{
		Name: "pos_session", Value: val, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600,
	})
}

func (a *app) readSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("pos_session")
	if err != nil {
		return session{}, false
	}
	parts := splitN(c.Value, '.', 2)
	if len(parts) != 2 {
		return session{}, false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || a.sign(string(raw)) != parts[1] {
		return session{}, false
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil || time.Now().Unix() > s.Exp {
		return session{}, false
	}
	return s, true
}

// --- handlers ---

func (a *app) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.readSession(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "login dulu")
			return
		}
		next(w, r.WithContext(withSession(r.Context(), s)))
	}
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		PIN  string `json:"pin"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, role, err := a.db.Login(req.Name, req.PIN)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "nama atau PIN salah")
		return
	}
	a.setSession(w, session{CashierID: id, Name: req.Name, Role: role, Exp: time.Now().Add(12 * time.Hour).Unix()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": role})
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "pos_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *app) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mustSession(r.Context()))
}

func (a *app) handleShiftOpen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OpeningCash int64 `json:"opening_cash"`
	}
	if !decode(w, r, &req) {
		return
	}
	s := mustSession(r.Context())
	id, err := a.db.OpenShift(s.CashierID, req.OpeningCash)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.log.Info("shift opened", "shift", id, "cashier", s.Name)
	writeJSON(w, http.StatusOK, map[string]any{"shift_id": id})
}

func (a *app) handleShiftClose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClosingCash int64  `json:"closing_cash"`
		Note        string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	s := mustSession(r.Context())
	id, expected, diff, err := a.db.CloseShift(s.CashierID, req.ClosingCash, req.Note)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.log.Info("shift closed", "shift", id, "expected", expected, "diff", diff)
	writeJSON(w, http.StatusOK, map[string]any{"shift_id": id, "expected": expected, "diff": diff})
}

func (a *app) handleProducts(w http.ResponseWriter, _ *http.Request) {
	type product struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Price int64  `json:"price"`
	}
	rows, err := a.db.Query(`SELECT id, name, price FROM products WHERE is_active = 1 ORDER BY id`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal membaca produk")
		return
	}
	defer rows.Close()
	out := []product{}
	for rows.Next() {
		var p product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price); err != nil {
			writeErr(w, http.StatusInternalServerError, "gagal membaca produk")
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"products": out}, rows.Err())
}

func (a *app) handleOrderCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table string `json:"table"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, orderNo, err := a.db.CreateOrder(req.Table)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"order_id": id, "order_no": orderNo})
}

func (a *app) handleItemAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID int64  `json:"product_id"`
		Qty       int64  `json:"qty"`
		Note      string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	orderID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || req.Qty <= 0 {
		writeErr(w, http.StatusBadRequest, "order/qty tidak valid")
		return
	}
	if err := a.db.AddItem(orderID, req.ProductID, req.Qty, req.Note); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *app) handlePay(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method    string `json:"method"`
		Amount    int64  `json:"amount"`
		Reference string `json:"reference"`
		Tendered  int64  `json:"tendered"`
	}
	if !decode(w, r, &req) {
		return
	}
	orderID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "order tidak valid")
		return
	}
	s := mustSession(r.Context())
	res, err := a.db.Pay(posstore.PayInput{
		OrderID:        orderID,
		CashierID:      s.CashierID,
		Method:         req.Method,
		Amount:         req.Amount,
		Reference:      req.Reference,
		Tendered:       req.Tendered,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	if res.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	a.log.Info("order paid", "order", orderID, "method", req.Method, "replayed", res.Replayed)
	writeJSON(w, http.StatusOK, map[string]any{"payment_id": res.PaymentID, "change": res.ChangeGiven})
}

func (a *app) handleVoid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "alasan void wajib")
		return
	}
	s := mustSession(r.Context())
	if s.Role != "admin" {
		writeErr(w, http.StatusForbidden, "hanya admin boleh void")
		return
	}
	orderID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "order tidak valid")
		return
	}
	if err := a.db.VoidOrder(orderID, s.CashierID, req.Reason); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *app) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, posstore.ErrConflict) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	a.log.Error("internal", "err", err)
	writeErr(w, http.StatusInternalServerError, "kesalahan internal")
}

// --- small plumbing (session ctx, json io, env) ---

type ctxKey int

const sessionKey ctxKey = 1

func withSession(ctx context.Context, s session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func mustSession(ctx context.Context) session {
	s, _ := ctx.Value(sessionKey).(session)
	return s
}

func decode[T any](w http.ResponseWriter, r *http.Request, v *T) bool {
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "json tidak valid")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any, extra ...error) {
	for _, e := range extra {
		if e != nil {
			writeErr(w, http.StatusInternalServerError, "kesalahan internal")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func seedAdmin(db *posstore.DB, log *slog.Logger) {
	name := os.Getenv("POS_SEED_ADMIN")
	pin := os.Getenv("POS_SEED_ADMIN_PIN")
	if name == "" || pin == "" {
		return
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cashiers`).Scan(&n)
	if n > 0 {
		return
	}
	if _, err := db.CreateCashier(name, pin, "admin"); err != nil {
		log.Warn("admin seed failed", "err", err)
		return
	}
	log.Info("admin cashier seeded", "name", name)
}

var _ = fmt.Sprintf // keep fmt if log lines change
