package portal

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/reconcile"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/store/storetest"
)

func TestClientRefDeterministicAndDistinct(t *testing.T) {
	s := New("kunci-pemasaran-cafe")
	a1 := s.ClientRef("AA:BB:CC:DD:EE:01")
	a2 := s.ClientRef("aa:bb:cc:dd:ee:01") // case-insensitive input
	b := s.ClientRef("aa:bb:cc:dd:ee:02")
	if a1 == "" || a1 != a2 {
		t.Fatalf("client_ref must be deterministic per MAC (case-insensitive): %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Fatal("different MACs must map to different pseudonyms")
	}
	if len(a1) != 64 { // hex(SHA-256)
		t.Fatalf("client_ref length = %d, want 64 hex chars", len(a1))
	}
	empty := New("") // no key = marketing sync disabled
	if got := empty.ClientRef("aa:bb:cc:dd:ee:01"); got != "" {
		t.Fatalf("empty key must disable client_ref, got %q", got)
	}
}

func TestSessionIDRandom(t *testing.T) {
	a, err := SessionID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SessionID()
	if a == b {
		t.Fatal("session ids must be random per call")
	}
	if len(a) != 24 { // hex(12 bytes)
		t.Fatalf("session id length = %d, want 24", len(a))
	}
}

func TestEncodePayloadSortedAndClean(t *testing.T) {
	got := EncodePayload(map[string]string{"contact": "a=b;c", "name": "Budi"})
	want := "contact=abc;name=Budi" // sorted keys, separators stripped
	if got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if EncodePayload(nil) != "" {
		t.Fatal("empty payload must be empty")
	}
}

// View reads the consent metadata the actor's handler wrote (the exact
// path the portal page and admin API rely on).
func TestViewReflectsAuthorizedSession(t *testing.T) {
	db := storetest.Open(t)
	if err := store.EnsureSeedZones(db, []store.SeedZone{{ID: 1, Name: "z1", Subnet: "10.20.1.0/24", Internet: true}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := store.UpsertSeenDevice(db, "aa:bb:cc:dd:ee:03", "hp-tamu", "br-guest", now); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertLease(db, "aa:bb:cc:dd:ee:03", "10.20.3.44", 2*time.Hour, now); err != nil {
		t.Fatal(err)
	}

	// Before consent: waiting, unauthorized.
	v, err := View(db, "aa:bb:cc:dd:ee:03", now)
	if err != nil {
		t.Fatal(err)
	}
	if v.Authorized || v.State != "waiting" || v.Zone != "" {
		t.Fatalf("pre-consent view = %+v", v)
	}

	// The actor handler's write path (consent metadata carried in cmd).
	h := reconcile.NewHandler(db, config.Default(), stubApplier{}, slog.Default())
	cmd := core.AuthorizeGuest{
		MAC:       "aa:bb:cc:dd:ee:03",
		TTL:       time.Hour,
		SessionID: "sess-1",
		TenantID:  "marketing",
		Marketing: true,
		Payload:   EncodePayload(map[string]string{"name": "Budi"}),
		Terms:     "2026-09",
		Lang:      "id",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if res := h.Handle(ctx, cmd); res.Err != nil {
		t.Fatalf("authorize: %v", res.Err)
	}

	v, err = View(db, "aa:bb:cc:dd:ee:03", now)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Authorized || !v.Marketing || v.TTL <= 0 {
		t.Fatalf("post-consent view = %+v", v)
	}
}

// stubApplier satisfies reconcile.Applier without touching a kernel.
type stubApplier struct{}

func (stubApplier) Apply(context.Context, []byte) (string, error) { return "stub", nil }
