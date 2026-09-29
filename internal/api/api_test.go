package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/reconcile"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/store/storetest"
)

type stubApplier struct{}

func (stubApplier) Apply(context.Context, []byte) (string, error) { return "stub", nil }

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	db := storetest.Open(t)
	if err := store.EnsureSeedZones(db, []store.SeedZone{
		{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true},
		{ID: 2, Name: "pos", Subnet: "10.20.2.0/24", Internet: true},
	}); err != nil {
		t.Fatal(err)
	}
	actor := core.NewActor(core.NewBus(16), reconcile.NewHandler(db, config.Default(), stubApplier{}, slog.Default()).Handle)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go actor.Run(ctx)

	s := &Server{DB: db, Actor: actor, Confirmer: nil, Log: slog.Default()}
	s.SetToken("test-token-1")
	return s, s.Handler()
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRejectsMissingAndWrongTokens(t *testing.T) {
	_, h := newTestServer(t)
	if rec := doJSON(t, h, "GET", "/api/v1/devices", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token -> %d, want 401", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/api/v1/devices", "salah", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token -> %d, want 401", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/api/v1/devices", "test-token-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("good token -> %d, want 200", rec.Code)
	}
}

func TestApproveDeviceRoundTrip(t *testing.T) {
	s, h := newTestServer(t)
	rec := doJSON(t, h, "POST", "/api/v1/devices/approve", "test-token-1",
		`{"mac":"AA:BB:CC:DD:EE:09","zone_id":2,"note":"meja 3"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve -> %d: %s", rec.Code, rec.Body.String())
	}
	// Canonicalized + visible in the device list.
	rec = doJSON(t, h, "GET", "/api/v1/devices?state=approved", "test-token-1", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "aa:bb:cc:dd:ee:09") {
		t.Fatalf("device list missing approved mac: %d %s", rec.Code, rec.Body.String())
	}
	// Unknown zone surfaces as a conflict (actor error), not a 500.
	rec = doJSON(t, h, "POST", "/api/v1/devices/approve", "test-token-1",
		`{"mac":"aa:bb:cc:dd:ee:0a","zone_id":9}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("bad zone -> %d, want 409: %s", rec.Code, rec.Body.String())
	}
	_ = s
}

func TestRevokeAndAuditTrail(t *testing.T) {
	_, h := newTestServer(t)
	// Approve then revoke: both are audited.
	if rec := doJSON(t, h, "POST", "/api/v1/devices/approve", "test-token-1",
		`{"mac":"aa:bb:cc:dd:ee:0b","zone_id":1}`); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, h, "POST", "/api/v1/guests/revoke", "test-token-1",
		`{"mac":"aa:bb:cc:dd:ee:0b"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	rec := doJSON(t, h, "GET", "/api/v1/audit?limit=10", "test-token-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: %d", rec.Code)
	}
	var out struct {
		Audit []struct {
			Action string `json:"action"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Audit) == 0 {
		t.Fatal("audit must record the actor-driven mutations")
	}
}

func TestVoucherCreateList(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, "POST", "/api/v1/vouchers", "test-token-1",
		`{"count":3,"duration_s":3600,"max_uses":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Codes []string `json:"codes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Codes) != 3 {
		t.Fatalf("codes = %v", out.Codes)
	}
	rec = doJSON(t, h, "GET", "/api/v1/vouchers", "test-token-1", "")
	if !strings.Contains(rec.Body.String(), out.Codes[0]) {
		t.Fatal("voucher list must contain the created code")
	}
}

func TestLoadTokenCreatesOnceAndReuses(t *testing.T) {
	db := storetest.Open(t)
	tok1, created, err := LoadToken(db)
	if err != nil || !created || tok1 == "" {
		t.Fatalf("first load: created=%v tok=%q err=%v", created, tok1, err)
	}
	tok2, created2, err := LoadToken(db)
	if err != nil || created2 || tok2 != tok1 {
		t.Fatalf("second load must reuse: created=%v same=%v err=%v", created2, tok1 == tok2, err)
	}
}

func TestGUIServedWithoutTokenAPINot(t *testing.T) {
	_, h := newTestServer(t)
	// The embedded GUI shell loads without a token (login page must
	// render before any credential exists).
	rec := doJSON(t, h, "GET", "/", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "kotacloud admin") {
		t.Fatalf("GET / -> %d, want the GUI shell: %s", rec.Code, rec.Body.String())
	}
	// But the API surface keeps its bearer gate.
	rec = doJSON(t, h, "GET", "/api/v1/devices", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/devices without token -> %d, want 401", rec.Code)
	}
}
