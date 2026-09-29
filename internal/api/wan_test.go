package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/store/storetest"
)

func TestWanGetDefaultsAndDetection(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, "GET", "/api/v1/network/wan", "test-token-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET wan -> %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// No posture recorded yet: no "wan" key, but the live detection
	// blocks must always be present (they answer "what do we have?").
	if _, ok := out["wan"]; ok {
		t.Fatalf("fresh db must not report a recorded posture: %v", out)
	}
	if _, ok := out["uplink"]; !ok {
		t.Fatal("uplink probe missing")
	}
	if _, ok := out["bridges"]; !ok {
		t.Fatal("bridges map missing")
	}
	if _, ok := out["bridges_ready"]; !ok {
		t.Fatal("bridges_ready missing")
	}
}

func TestWanPostPersistsAndAudits(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, "POST", "/api/v1/network/wan", "test-token-1",
		`{"wan":{"mode":"dhcp"},"iface":"lo"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST wan -> %d: %s", rec.Code, rec.Body.String())
	}

	// GET must now report the recorded posture ("lo" exists everywhere,
	// so the interface check passes even on headless CI boxes).
	rec = doJSON(t, h, "GET", "/api/v1/network/wan", "test-token-1", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"mode":"dhcp"`) {
		t.Fatalf("posture not persisted: %d %s", rec.Code, rec.Body.String())
	}

	// The mutation is audited (settings-level writes leave the same
	// tamper-evident trail as actor commands).
	rec = doJSON(t, h, "GET", "/api/v1/audit?limit=10", "test-token-1", "")
	if !strings.Contains(rec.Body.String(), "wan.config") {
		t.Fatalf("audit missing wan.config: %s", rec.Body.String())
	}
}

func TestWanPostValidation(t *testing.T) {
	_, h := newTestServer(t)

	// Invalid mode -> 400.
	if rec := doJSON(t, h, "POST", "/api/v1/network/wan", "test-token-1",
		`{"wan":{"mode":"5g-nr"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad mode -> %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// Unknown iface -> 400.
	if rec := doJSON(t, h, "POST", "/api/v1/network/wan", "test-token-1",
		`{"wan":{"mode":"static"},"iface":"eth9"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad iface -> %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestShieldGETFailsSoft(t *testing.T) {
	_, h := newTestServer(t)
	// On the test box no nft binary exists — the read fails and the
	// handler must still answer 200 with installed=false (fail soft),
	// NOT a 500: a missing shield is the message, not an error page.
	rec := doJSON(t, h, "GET", "/api/v1/network/doh", "test-token-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET doh -> %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"Installed":false`) {
		t.Fatalf("body = %s, want installed=false", rec.Body.String())
	}
	// The monitoring surface stays behind the bearer gate.
	rec = doJSON(t, h, "GET", "/api/v1/network/doh", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token -> %d, want 401", rec.Code)
	}
}

func TestRecordAuditAnchorsAndChains(t *testing.T) {
	db := storetest.Open(t)
	now := time.Now()
	if err := store.RecordAudit(db, "test", "wan.config", "eth0", "a -> b", now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAudit(db, "test", "wan.config", "eth0", "b -> c", now); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListAudit(db, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Diff != "b -> c" || rows[1].Diff != "a -> b" {
		t.Fatalf("audit rows = %+v", rows)
	}
}
