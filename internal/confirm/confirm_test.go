package confirm

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestManager(t *testing.T) (*Manager, *appliedLog) {
	t.Helper()
	dir := t.TempDir()
	applied := &appliedLog{}
	m := NewManager(dir, func(_ context.Context, rs []byte) error {
		applied.record(rs)
		return nil
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	t.Cleanup(func() { m.stopTimerLocked() })
	return m, applied
}

// appliedLog is a goroutine-safe record of rulesets the fake applier
// received — the timeout timer fires on its own goroutine, so plain
// slices would race under -race.
type appliedLog struct {
	mu    sync.Mutex
	rules [][]byte
}

func (a *appliedLog) record(rs []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, append([]byte(nil), rs...))
}

func (a *appliedLog) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.rules)
}

func (a *appliedLog) last() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.rules) == 0 {
		return nil
	}
	return a.rules[len(a.rules)-1]
}

func goodRuleset(tag string) []byte { return []byte("ruleset-" + tag) }

func TestBeginConfirmCycle(t *testing.T) {
	m, applied := newTestManager(t)
	ctx := context.Background()

	deadline, err := m.Begin(ctx, "PutZonePolicy@1", "admin zone policy", goodRuleset("old"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if time.Until(deadline) > 61*time.Second || time.Until(deadline) < 55*time.Second {
		t.Fatalf("deadline %v is not ~60s out", deadline)
	}

	// pending.json + snapshot exist on disk.
	if _, err := os.Stat(filepath.Join(m.Dir, pendingFile)); err != nil {
		t.Fatalf("pending.json missing: %v", err)
	}
	snap, err := os.ReadFile(filepath.Join(m.Dir, snapshotFile))
	if err != nil || string(snap) != "ruleset-old" {
		t.Fatalf("snapshot = %q, %v", snap, err)
	}

	if err := m.Confirm("PutZonePolicy@1"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, pendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending.json survived confirm: %v", err)
	}
	if _, ok := m.Deadline(); ok {
		t.Fatal("Deadline() reports a trial after confirm")
	}
	if applied.count() != 0 {
		t.Fatalf("confirm must not re-apply anything, applied %d", applied.count())
	}
}

func TestTimeoutRollsBackToSnapshot(t *testing.T) {
	m, applied := newTestManager(t)
	m.Window = 40 * time.Millisecond
	ctx := context.Background()

	if _, err := m.Begin(ctx, "PutZonePolicy@2", "admin zone policy", goodRuleset("old")); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Wait past the window: the timer must roll back on its own.
	deadline := time.Now().Add(2 * time.Second)
	for applied.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if applied.count() != 1 || string(applied.last()) != "ruleset-old" {
		t.Fatalf("rollback applied %d rulesets, want the old one", applied.count())
	}
	if _, ok := m.Deadline(); ok {
		t.Fatal("trial still active after timeout rollback")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, pendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending.json survived rollback: %v", err)
	}
}

func TestRollbackIsIdempotent(t *testing.T) {
	m, applied := newTestManager(t)
	ctx := context.Background()
	if _, err := m.Begin(ctx, "X@1", "r", goodRuleset("old")); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := m.Rollback(ctx, "X@1", "test"); err != nil {
			t.Fatalf("rollback %d: %v", i, err)
		}
	}
	if applied.count() != 1 {
		t.Fatalf("rollback applied %d times, want exactly 1", applied.count())
	}
	// Rolling back an unknown/already-resolved change is a no-op success.
	if err := m.Rollback(ctx, "Other@9", "test"); err != nil {
		t.Fatalf("unknown-change rollback must be a no-op, got %v", err)
	}
}

func TestRecoverRollsBackOrphanedPending(t *testing.T) {
	m, applied := newTestManager(t)
	ctx := context.Background()

	// Simulate a crash: write the marker by hand (as the dead process
	// would have left it), then Recover on a fresh boot.
	p := Pending{ChangeID: "PutZonePolicy@3", Deadline: time.Now().Add(-time.Second),
		RiskReason: "r", Snapshot: snapshotFile, StartedAt: time.Now().Add(-time.Minute)}
	if err := m.persistLocked(&p); err != nil {
		t.Fatalf("seed pending.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir, snapshotFile), goodRuleset("crashed-old"), 0o640); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	recovered, err := m.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !recovered {
		t.Fatal("Recover must report that a rollback happened")
	}
	if applied.count() != 1 || string(applied.last()) != "ruleset-crashed-old" {
		t.Fatalf("boot rollback applied %d rulesets, want the crashed process's snapshot", applied.count())
	}
	if _, err := os.Stat(filepath.Join(m.Dir, pendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending.json survived boot rollback: %v", err)
	}
}

func TestRecoverCleanBootIsNoop(t *testing.T) {
	m, applied := newTestManager(t)
	recovered, err := m.Recover(context.Background())
	if err != nil || recovered {
		t.Fatalf("clean boot: recovered=%v err=%v, want false/nil", recovered, err)
	}
	if applied.count() != 0 {
		t.Fatal("clean boot must not apply anything")
	}
}

func TestRecoverCorruptPendingFailsSafe(t *testing.T) {
	m, _ := newTestManager(t)
	if err := os.WriteFile(filepath.Join(m.Dir, pendingFile), []byte("{not json"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := m.Recover(context.Background()); err == nil {
		t.Fatal("corrupt pending.json must fail loudly (manual rollback), not silently proceed")
	}
}

func TestBeginRefusesSecondTrial(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if _, err := m.Begin(ctx, "A@1", "r", goodRuleset("a")); err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	if _, err := m.Begin(ctx, "B@1", "r", goodRuleset("b")); err == nil {
		t.Fatal("second trial while one is active must be refused")
	}
	// Confirm, then the next trial may start.
	if err := m.Confirm("A@1"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, err := m.Begin(ctx, "B@1", "r", goodRuleset("b")); err != nil {
		t.Fatalf("trial after confirm refused: %v", err)
	}
}

func TestConfirmWrongIDRejected(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if _, err := m.Begin(ctx, "A@1", "r", goodRuleset("a")); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := m.Confirm("B@1"); err == nil {
		t.Fatal("confirming a different change must be rejected")
	}
	if err := m.Confirm("B@1"); err == nil || !errors.Is(err, err) {
		t.Fatal("no-pending confirm must also be rejected")
	}
}

func TestSnapshotWrittenBeforePendingMarker(t *testing.T) {
	// Crash-window contract from §4.7: snapshot first, pending.json
	// second — verified by inspecting mtimes after a Begin.
	m, _ := newTestManager(t)
	ctx := context.Background()
	if _, err := m.Begin(ctx, "A@1", "r", goodRuleset("a")); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	snapInfo, err := os.Stat(filepath.Join(m.Dir, snapshotFile))
	if err != nil {
		t.Fatalf("snapshot stat: %v", err)
	}
	pendInfo, err := os.Stat(filepath.Join(m.Dir, pendingFile))
	if err != nil {
		t.Fatalf("pending stat: %v", err)
	}
	if pendInfo.ModTime().Before(snapInfo.ModTime()) {
		t.Fatal("pending.json was written before the snapshot — crash window inverted")
	}
	// And the persisted marker must round-trip.
	raw, _ := os.ReadFile(filepath.Join(m.Dir, pendingFile))
	var p Pending
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("pending.json not valid JSON: %v", err)
	}
	if p.ChangeID != "A@1" || p.Snapshot != snapshotFile {
		t.Fatalf("pending.json content = %+v", p)
	}
}
