package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/confirm"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/nft"
	"kotacloud-portal/internal/store"
)

// trialActive reports whether the manager still holds the trial.
func trialActive(m *confirm.Manager) bool {
	_, ok := m.Deadline()
	return ok
}

// newConfirmTestHandler wires a handler with a short-window confirm
// manager over a temp dir, plus the zone rows policy commands need.
func newConfirmTestHandler(t *testing.T) (*Handler, *stubApplier, *confirm.Manager, string) {
	t.Helper()
	h, ap, _ := newTestHandler(t)
	for _, z := range []store.SeedZone{
		{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true},
		{ID: 2, Name: "pos", Subnet: "10.20.2.0/24", Internet: true},
	} {
		if err := store.EnsureSeedZones(h.DB, []store.SeedZone{z}); err != nil {
			t.Fatalf("seed zone %d: %v", z.ID, err)
		}
	}
	dir := t.TempDir()
	m := confirm.NewManager(dir, func(ctx context.Context, rs []byte) error {
		_, err := ap.Apply(ctx, rs) // rollback goes through the same stub
		return err
	}, nil)
	m.Window = 60 * time.Millisecond
	h.Confirm = m
	return h, ap, m, dir
}

func TestRiskyCommandSetsDeadline(t *testing.T) {
	h, _, m, _ := newConfirmTestHandler(t)
	ctx := context.Background()

	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 1, Internet: true}) // Admin zone = risky (ADR-006)
	if res.Err != nil {
		t.Fatalf("Handle risky: %v", res.Err)
	}
	if res.Deadline.IsZero() {
		t.Fatal("IF-02: risky command must carry a non-zero Result.Deadline")
	}
	if _, ok := m.Deadline(); !ok {
		t.Fatal("confirm manager lost the trial")
	}
}

func TestNonRiskyCommandHasNoDeadline(t *testing.T) {
	h, _, _, _ := newConfirmTestHandler(t)
	ctx := context.Background()

	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 2, Internet: true}) // POS zone: not risky
	if res.Err != nil {
		t.Fatalf("Handle: %v", res.Err)
	}
	if !res.Deadline.IsZero() {
		t.Fatal("non-risky command must not start a confirm trial")
	}
	// Guest authorize never trips the confirm path either.
	res = h.Handle(ctx, core.AuthorizeGuest{MAC: "aa:bb:cc:dd:12:01", TTL: time.Hour})
	if res.Err != nil || !res.Deadline.IsZero() {
		t.Fatalf("authorize = %+v, want no deadline", res)
	}
}

func TestRiskyCommandRejectedByNFTCarriesNoTrial(t *testing.T) {
	h, ap, m, _ := newConfirmTestHandler(t)
	ctx := context.Background()

	ap.fail = &nft.CheckError{Path: "kcp.nft", Output: "syntax error"} // real type for errors.As
	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 1, Internet: true})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "config.rejected") {
		t.Fatalf("expected config.rejected, got %v", res.Err)
	}
	if !res.Deadline.IsZero() {
		t.Fatal("a rejected ruleset must not open a confirm trial")
	}
	if _, ok := m.Deadline(); ok {
		t.Fatal("trial opened despite rejection")
	}
}

func TestConfirmClosesTheTrial(t *testing.T) {
	h, _, m, _ := newConfirmTestHandler(t)
	ctx := context.Background()

	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 1})
	if res.Err != nil {
		t.Fatalf("Handle: %v", res.Err)
	}
	if err := m.Confirm(res.ChangeID); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, ok := m.Deadline(); ok {
		t.Fatal("trial still active after confirm")
	}
}

func TestTimeoutRollsBackToLastGoodRuleset(t *testing.T) {
	h, ap, m, dir := newConfirmTestHandler(t)
	ctx := context.Background()

	// First a benign command establishes the last-good snapshot.
	if res := h.Handle(ctx, core.AuthorizeGuest{MAC: "aa:bb:cc:dd:12:02", TTL: time.Hour}); res.Err != nil {
		t.Fatalf("seed command: %v", res.Err)
	}
	seedCount := ap.count()

	// Then the risky one goes on trial and times out.
	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 1, Internet: true})
	if res.Err != nil || res.Deadline.IsZero() {
		t.Fatalf("risky handle = %+v", res)
	}
	deadline := time.Now().Add(2 * time.Second)
	for (ap.count() == seedCount || trialActive(m)) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ap.count() <= seedCount {
		t.Fatal("timeout never re-applied the last-good snapshot")
	}
	if trialActive(m) {
		t.Fatal("trial still active after rollback")
	}
	rollback := string(ap.last())
	if !strings.Contains(rollback, "table inet kcp_zones") {
		t.Fatalf("rollback output is not a ruleset: %.80s", rollback)
	}
	// pending.json cleared.
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatalf("pending.json survived rollback: %v", err)
	}
}

// TestBootRecoveryWithReconcileSnapshot ties the two halves together:
// the snapshot the manager rolls back to is the reconcile handler's
// last-good render, byte for byte.
func TestBootRecoveryWithReconcileSnapshot(t *testing.T) {
	h, ap, _, dir := newConfirmTestHandler(t) // m's timer is irrelevant here: we crash-simulate with `booted`
	ctx := context.Background()

	if res := h.Handle(ctx, core.AuthorizeGuest{MAC: "aa:bb:cc:dd:12:03", TTL: time.Hour}); res.Err != nil {
		t.Fatalf("seed: %v", res.Err)
	}
	lastGood := append([]byte(nil), ap.last()...)

	res := h.Handle(ctx, core.PutZonePolicy{ZoneID: 1, Internet: true})
	if res.Err != nil || res.Deadline.IsZero() {
		t.Fatalf("risky handle = %+v", res)
	}
	// Crash: instead of Confirm or timeout, a fresh manager boots and
	// finds the orphaned pending.json.
	booted := confirm.NewManager(dir, func(ctx context.Context, rs []byte) error {
		_, err := ap.Apply(ctx, rs)
		return err
	}, nil)
	recovered, err := booted.Recover(ctx)
	if err != nil || !recovered {
		t.Fatalf("Recover = %v, %v", recovered, err)
	}
	rollback := ap.last()
	if string(rollback) != string(lastGood) {
		t.Fatal("boot rollback did not restore the last-good ruleset byte-for-byte")
	}
}
