// Package confirm implements the commit-confirm half of MOD-RECON
// (§4.7, ADR-006): risky changes are applied provisionally and must be
// confirmed before their Deadline, or the previous ruleset (the
// "last-good" snapshot) is re-applied automatically.
//
// Crash safety comes from the filesystem, not memory: while a change is
// pending, /run/kcportal/pending.json exists. A boot that finds that
// file knows the last process died (or timed out) with an unconfirmed
// change and rolls back to the snapshot it references BEFORE serving.
package confirm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultWindow is the confirm window (§4.7: "timer 60 s").
const DefaultWindow = 60 * time.Second

// files, relative to Dir (tmpfs, PD-4):
const (
	pendingFile  = "pending.json"
	snapshotFile = "last-good.nft"
	// Keep the extension-less form too: Apply writes kcp.nft.
	currentFile = "kcp.nft"
)

// Pending is the persisted state of one unconfirmed risky change.
type Pending struct {
	ChangeID   string    `json:"change_id"`   // which command is on trial
	Deadline   time.Time `json:"deadline"`    // confirm before this
	RiskReason string    `json:"risk_reason"` // ADR-006 label for the GUI
	Snapshot   string    `json:"snapshot"`    // snapshot filename (last-good.nft)
	StartedAt  time.Time `json:"started_at"`
}

// Manager owns the confirm lifecycle. It is safe for concurrent use:
// Confirm/Deadline/Active come from HTTP handlers and tests, the timer
// runs on its own goroutine, and Rollback can come from any of the three.
type Manager struct {
	Dir    string
	Window time.Duration
	Log    *slog.Logger

	// ApplySnapshot re-installs a snapshot's ruleset. It is the
	// nft.Applier (or a stub in tests); a rollback that fails here is
	// logged loudly and retried by the drift loop, because the desired
	// state source (state.db) is untouched either way.
	ApplySnapshot func(ctx context.Context, ruleset []byte) error

	mu      sync.Mutex
	timer   *time.Timer
	current *Pending
}

// NewManager builds a Manager over Dir.
func NewManager(dir string, apply func(ctx context.Context, ruleset []byte) error, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{Dir: dir, Window: DefaultWindow, ApplySnapshot: apply, Log: log}
}

// Begin marks a risky change as on trial: persists pending.json and the
// last-good snapshot, starts the confirm timer. It refuses to start a
// second trial while one is active — the state actor serialises
// commands, so this only guards against programming errors.
func (m *Manager) Begin(ctx context.Context, changeID, riskReason string, lastGood []byte) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		return time.Time{}, fmt.Errorf("confirm: change %s already on trial until %s",
			m.current.ChangeID, m.current.Deadline.Format(time.RFC3339))
	}
	if err := os.MkdirAll(m.Dir, 0o750); err != nil {
		return time.Time{}, fmt.Errorf("confirm: mkdir: %w", err)
	}

	window := m.Window
	if window <= 0 {
		window = DefaultWindow
	}
	p := &Pending{
		ChangeID:   changeID,
		Deadline:   time.Now().Add(window),
		RiskReason: riskReason,
		Snapshot:   snapshotFile,
		StartedAt:  time.Now(),
	}

	// Order matters (crash windows, §4.7): snapshot first, pending.json
	// second. A crash between the two leaves no pending marker — the
	// change was never announced, nothing to confirm, the snapshot is
	// merely fresher. A crash after both is the recover path.
	if err := os.WriteFile(filepath.Join(m.Dir, snapshotFile), lastGood, 0o640); err != nil {
		return time.Time{}, fmt.Errorf("confirm: write snapshot: %w", err)
	}
	if err := m.persistLocked(p); err != nil {
		return time.Time{}, err
	}

	m.current = p
	m.timer = time.AfterFunc(window, func() { m.onTimeout(p) })
	m.Log.Info("risky change on trial — confirm required",
		"change", changeID, "reason", riskReason, "deadline", p.Deadline.Format(time.RFC3339))
	return p.Deadline, nil
}

// Confirm accepts the pending change: clears the timer, removes
// pending.json, and keeps the (now confirmed) ruleset running. The
// snapshot stays as the new last-good baseline.
func (m *Manager) Confirm(changeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return fmt.Errorf("confirm: no change pending")
	}
	if m.current.ChangeID != changeID {
		return fmt.Errorf("confirm: change %s is not the pending one (%s)", changeID, m.current.ChangeID)
	}
	m.stopTimerLocked()
	m.current = nil
	if err := os.Remove(filepath.Join(m.Dir, pendingFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("confirm: remove pending.json: %w", err)
	}
	m.Log.Info("risky change confirmed", "change", changeID)
	return nil
}

// onTimeout fires when the window lapses without confirmation.
func (m *Manager) onTimeout(p *Pending) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Rollback(ctx, p.ChangeID, "confirm window expired"); err != nil {
		m.Log.Error("rollback after timeout FAILED — drift loop must retry", "change", p.ChangeID, "err", err)
	}
}

// Rollback re-applies the snapshot and clears the pending marker.
// Idempotent: rolling back an already-rolled-back change is a no-op
// success (the timer, the boot path, and the GUI can all race here).
func (m *Manager) Rollback(ctx context.Context, changeID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil || m.current.ChangeID != changeID {
		return nil // already resolved
	}
	return m.rollbackLocked(ctx, reason)
}

// rollbackLocked does the actual work; callers hold m.mu.
func (m *Manager) rollbackLocked(ctx context.Context, reason string) error {
	snap, err := os.ReadFile(filepath.Join(m.Dir, snapshotFile))
	if err != nil {
		return fmt.Errorf("confirm: read snapshot: %w", err)
	}
	if m.ApplySnapshot != nil {
		if err := m.ApplySnapshot(ctx, snap); err != nil {
			return fmt.Errorf("confirm: apply snapshot: %w", err)
		}
	}
	m.stopTimerLocked()
	m.current = nil
	if err := os.Remove(filepath.Join(m.Dir, pendingFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("confirm: remove pending.json: %w", err)
	}
	m.Log.Warn("rolled back to last-good ruleset", "reason", reason)
	return nil
}

// Recover is the boot path (§4.7 "tahan crash"): a pending.json that
// survived to boot means the previous process never confirmed its risky
// change — roll it back immediately, before the daemon serves anything.
// The in-memory trial state does not exist at boot, so Recover adopts
// the persisted marker as the active trial and rolls it back.
func (m *Manager) Recover(ctx context.Context) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(m.Dir, pendingFile))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // clean boot
		}
		return false, fmt.Errorf("confirm: read pending.json: %w", err)
	}
	var p Pending
	if err := json.Unmarshal(raw, &p); err != nil {
		// Corrupt marker: treat as unconfirmed (fail-safe), but we cannot
		// know which snapshot generation it references — refuse to guess.
		return false, fmt.Errorf("confirm: pending.json corrupt, manual rollback required: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = &p // adopt the crashed process's trial so the guard sees it
	if err := m.rollbackLocked(ctx, "unconfirmed change found at boot"); err != nil {
		return true, err
	}
	return true, nil
}

// Active reports the active trial verbatim — the GUI needs change_id
// (to POST /changes/confirm) and risk_reason (to show what is on
// trial), not just the deadline. The copy is safe: Pending is values.
func (m *Manager) Active() (Pending, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return Pending{}, false
	}
	return *m.current, true
}

// Deadline reports the active trial's deadline (GET /changes/pending,
// §7.2) or false when nothing is pending.
func (m *Manager) Deadline() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return time.Time{}, false
	}
	return m.current.Deadline, true
}

// persistLocked writes pending.json atomically (tmp + rename), the same
// contract the design demands of every generated file.
func (m *Manager) persistLocked(p *Pending) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("confirm: encode pending: %w", err)
	}
	tmp := filepath.Join(m.Dir, pendingFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return fmt.Errorf("confirm: write pending.tmp: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(m.Dir, pendingFile)); err != nil {
		return fmt.Errorf("confirm: rename pending.json: %w", err)
	}
	return nil
}

func (m *Manager) stopTimerLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
}

// ErrNoPending is returned by readers that require an active trial.
var ErrNoPending = errors.New("confirm: no pending change")
