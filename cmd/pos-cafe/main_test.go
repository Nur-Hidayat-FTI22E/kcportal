package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/pos/printer"
	posstore "kotacloud-portal/internal/pos/store"
)

// newTestApp builds the app on a temp pos.db with a seeded admin+cashier.
func newTestApp(t *testing.T) *app {
	t.Helper()
	db, err := posstore.Open(filepath.Join(t.TempDir(), "pos.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSeedCatalog(map[string]int64{"Kopi Susu": 18000}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateCashier("budi", "1234", "kasir"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateCashier("ratna", "admin1", "admin"); err != nil {
		t.Fatal(err)
	}
	return &app{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), secret: newSecret()}
}

func muxOf(a *app) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/shift/open", a.auth(a.handleShiftOpen))
	mux.HandleFunc("POST /api/shift/close", a.auth(a.handleShiftClose))
	mux.HandleFunc("GET /api/products", a.auth(a.handleProducts))
	mux.HandleFunc("POST /api/orders", a.auth(a.handleOrderCreate))
	mux.HandleFunc("POST /api/orders/{id}/items", a.auth(a.handleItemAdd))
	mux.HandleFunc("POST /api/orders/{id}/pay", a.auth(a.handlePay))
	mux.HandleFunc("POST /api/orders/{id}/void", a.auth(a.handleVoid))
	return mux
}

func postJSON(t *testing.T, h http.Handler, path, cookie, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("Idempotency-Key", fmt.Sprintf("test-%d", timeNowNano()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func timeNowNano() int64 { return int64(float64(os.Getpid())*1e6) + int64(len(os.Args)) }

func loginCookie(t *testing.T, h http.Handler, name, pin string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"name":"`+name+`","pin":"`+pin+`"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login %s -> %d: %s", name, resp.StatusCode, b)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "pos_session" {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// The M4.3 acceptance flow, end to end.
func TestFullPosFlow(t *testing.T) {
	a := newTestApp(t)
	h := muxOf(a)

	// Wrong PIN rejected.
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"name":"budi","pin":"9999"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatal("wrong pin must be 401")
	}

	cookie := loginCookie(t, h, "budi", "1234")

	// Products seeded.
	req = httptest.NewRequest("GET", "/api/products", nil)
	req.Header.Set("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Kopi Susu") {
		t.Fatalf("catalog missing: %s", rec.Body.String())
	}

	// Shift open → order → items → pay cash.
	if resp := postJSON(t, h, "/api/shift/open", cookie, `{"opening_cash":100000}`); resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("shift open -> %d: %s", resp.StatusCode, b)
	}
	// Second open must hit the DB's single-open rule (409).
	if resp := postJSON(t, h, "/api/shift/open", cookie, `{"opening_cash":1}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("double open -> %d, want 409", resp.StatusCode)
	}

	var order struct {
		OrderID int64  `json:"order_id"`
		OrderNo string `json:"order_no"`
	}
	if resp := postJSON(t, h, "/api/orders", cookie, `{"table":"M1"}`); resp.StatusCode != 200 {
		t.Fatalf("order create: %d", resp.StatusCode)
	} else {
		_ = json.NewDecoder(resp.Body).Decode(&order)
	}
	if !strings.HasSuffix(order.OrderNo, "-0001") {
		t.Fatalf("order_no = %q", order.OrderNo)
	}
	if resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/items", order.OrderID), cookie, `{"product_id":1,"qty":2}`); resp.StatusCode != 200 {
		t.Fatalf("item add: %d", resp.StatusCode)
	}

	// Underpay rejected.
	resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/pay", order.OrderID), cookie, `{"method":"cash","amount":1,"tendered":1}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("underpay -> %d, want 409", resp.StatusCode)
	}
	// Proper cash pay: 2 × 18000 = 36000, tendered 50000 → change 14000.
	// Fixed key so the replay below hits the same idempotency row.
	req = httptest.NewRequest("POST", fmt.Sprintf("/api/orders/%d/pay", order.OrderID), strings.NewReader(`{"method":"cash","amount":36000,"tendered":50000}`))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Idempotency-Key", "replay-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp = rec.Result()
	var pay struct {
		PaymentID int64 `json:"payment_id"`
		Change    int64 `json:"change"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pay)
	if resp.StatusCode != 200 || pay.Change != 14000 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("pay -> %d %s", resp.StatusCode, b)
	}
	// Idempotent replay: same key → same payment, marked replayed.
	req2 := httptest.NewRequest("POST", fmt.Sprintf("/api/orders/%d/pay", order.OrderID), strings.NewReader(`{"method":"cash","amount":36000,"tendered":50000}`))
	req2.Header.Set("Cookie", cookie)
	req2.Header.Set("Idempotency-Key", "replay-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Result().Header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay must be marked")
	}
	// Paid order cannot be paid again with a NEW key.
	resp = postJSON(t, h, fmt.Sprintf("/api/orders/%d/pay", order.OrderID), cookie, `{"method":"cash","amount":36000,"tendered":50000}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("double pay (new key) -> %d, want 409", resp.StatusCode)
	}

	// A queued receipt job exists (same tx as the payment).
	jobID, printedOrder, err := a.db.NextQueuedReceipt()
	if err != nil || jobID == 0 || printedOrder != order.OrderID {
		t.Fatalf("print job missing: job=%d order=%d err=%v", jobID, printedOrder, err)
	}

	// Void rules on a SECOND order: kasir forbidden, admin OK — then a
	// voided order refuses payment.
	var voidOrder struct {
		OrderID int64 `json:"order_id"`
	}
	_ = json.NewDecoder(postJSON(t, h, "/api/orders", cookie, `{}`).Body).Decode(&voidOrder)
	if resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/void", voidOrder.OrderID), cookie, `{"reason":"salah"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("kasir void -> %d, want 403", resp.StatusCode)
	}
	adminCookie := loginCookie(t, h, "ratna", "admin1")
	if resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/void", voidOrder.OrderID), adminCookie, `{"reason":"tes void"}`); resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin void -> %d: %s", resp.StatusCode, b)
	}
	if resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/pay", voidOrder.OrderID), cookie, `{"method":"cash","amount":36000,"tendered":40000}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("pay voided order -> %d, want 409", resp.StatusCode)
	}

	// Shift close: expected = opening (100000) + cash paid (36000) — the
	// QRIS/voided orders never touch the drawer.
	resp = postJSON(t, h, "/api/shift/close", cookie, `{"closing_cash":136000}`)
	var close struct {
		Expected int64 `json:"expected"`
		Diff     int64 `json:"diff"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&close)
	if resp.StatusCode != 200 || close.Expected != 136000 || close.Diff != 0 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("close -> %d %s", resp.StatusCode, b)
	}
}

// The printer worker drains a queued job into the driver.
func TestPrinterWorkerDrainsJob(t *testing.T) {
	a := newTestApp(t)
	h := muxOf(a)
	cookie := loginCookie(t, h, "budi", "1234")
	if resp := postJSON(t, h, "/api/shift/open", cookie, `{"opening_cash":0}`); resp.StatusCode != 200 {
		t.Fatalf("shift open: %d", resp.StatusCode)
	}
	var order struct {
		OrderID int64 `json:"order_id"`
	}
	resp := postJSON(t, h, "/api/orders", cookie, `{}`)
	_ = json.NewDecoder(resp.Body).Decode(&order)
	if resp := postJSON(t, h, fmt.Sprintf("/api/orders/%d/items", order.OrderID), cookie, `{"product_id":1,"qty":1}`); resp.StatusCode != 200 {
		t.Fatalf("item add: %d", resp.StatusCode)
	}
	resp = postJSON(t, h, fmt.Sprintf("/api/orders/%d/pay", order.OrderID), cookie, `{"method":"qris","amount":18000,"reference":"QR-123"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("qris pay: %d", resp.StatusCode)
	}

	// Fake driver: bytes arrive on a channel — no data race with the
	// polling test goroutine.
	printed := make(chan []byte, 4)
	fake := fakeDriver{out: printed}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		printer.Worker(a.db, fake, func(string, ...any) {})(stop)
	}()
	var got []byte
	select {
	case got = <-printed:
	case <-timeAfterChan(3 * time.Second):
		t.Fatal("worker never printed")
	}
	close(stop)
	<-done
	if !bytes.Contains(got, []byte("KOTACLOUD")) || !bytes.Contains(got, []byte("18000")) {
		t.Fatalf("receipt bytes wrong: %q", got)
	}
	jobID, _, err := a.db.NextQueuedReceipt()
	if err != nil || jobID != 0 {
		t.Fatalf("job not drained: %d %v", jobID, err)
	}
}

type fakeDriver struct{ out chan<- []byte }

func (f fakeDriver) Write(p []byte) error {
	cp := append([]byte(nil), p...)
	f.out <- cp
	return nil
}
func (f fakeDriver) Close() error { return nil }

func timeAfterChan(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	time.AfterFunc(d, func() { ch <- time.Now() })
	return ch
}

// Receipt rendering folds non-ASCII and keeps the money columns.
func TestRender58Columns(t *testing.T) {
	r := posstore.ReceiptData{
		OrderNo: "260930-0007",
		Lines: []posstore.ReceiptLine{
			{Name: "Kopi ☕ Susu", Qty: 2, Unit: 18000},
		},
		Total: 36000, Method: "cash", Tendered: 40000, Change: 4000,
	}
	b := printer.Render58(r)
	s := string(b)
	if !strings.Contains(s, "Kopi ? Susu") {
		t.Fatalf("non-ASCII must fold: %q", s)
	}
	for _, want := range []string{"36000", "40000", "4000", "260930-0007"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %q", want, s)
		}
	}
	for _, line := range strings.Split(s, "\n") {
		if runeLen(line) > 32 {
			t.Fatalf("line exceeds 32 columns: %q", line)
		}
	}
}

func runeLen(s string) int { return len([]rune(strings.TrimRight(s, "\r"))) }

// session cookie tamper → 401.
func TestSessionTamperRejected(t *testing.T) {
	a := newTestApp(t)
	h := muxOf(a)
	cookie := loginCookie(t, h, "budi", "1234")
	parts := strings.SplitN(cookie, "=", 2)
	val := parts[1]
	tampered := "pos_session=" + flipHex(val)
	req := httptest.NewRequest("GET", "/api/products", nil)
	req.Header.Set("Cookie", tampered)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatal("tampered cookie must be 401")
	}
	_ = tls.VersionTLS12
	_ = net.IPv4len
}

func flipHex(s string) string {
	if len(s) < 4 || s[0] != 'e' {
		return "0" + s
	}
	return "f" + s[1:]
}

func timeNow() time.Time { return time.Now() }
