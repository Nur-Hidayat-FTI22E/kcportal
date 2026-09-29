package reconcile

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/nft"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/store/storetest"
)

// stubApplier records every ruleset handed to Apply; it stands in for
// nft.Applier so tests exercise the full command -> db -> Plan -> render
// pipeline without a kernel. Goroutine-safe: confirm-rollbacks fire on
// the manager's timer goroutine.
type stubApplier struct {
	mu       sync.Mutex
	rulesets [][]byte
	fail     error // when set, Apply returns it (simulating nft -c rejection)
}

func (s *stubApplier) Apply(_ context.Context, rs []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return "", s.fail
	}
	s.rulesets = append(s.rulesets, append([]byte(nil), rs...))
	return "/run/kcportal/kcp.nft", nil
}

func (s *stubApplier) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rulesets)
}

func (s *stubApplier) last() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rulesets) == 0 {
		return nil
	}
	return s.rulesets[len(s.rulesets)-1]
}

func newTestHandler(t *testing.T) (*Handler, *stubApplier, core.Command) {
	t.Helper()
	db := storetest.Open(t)
	seeds := make([]store.SeedZone, 0, len(config.Default().Zones))
	for _, z := range config.Default().Zones {
		if z.ID <= 0 {
			continue // waiting is virtual (devices.state), not a zones row
		}
		seeds = append(seeds, store.SeedZone{ID: z.ID, Name: z.Name, Subnet: z.Subnet, Internet: z.Internet})
	}
	if err := store.EnsureSeedZones(db, seeds); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	ap := &stubApplier{}
	h := NewHandler(db, config.Default(), ap, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	h.Now = func() time.Time { return time.Unix(1_700_000_000, 0) } // fixed clock
	return h, ap, nil
}

func TestApproveCommandProducesMacZoneRule(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	ctx := context.Background()

	res := h.Handle(ctx, core.ApproveDevice{MAC: "aa:bb:cc:dd:00:0a", ZoneID: 2, Note: "POS terminal"})
	if res.Err != nil {
		t.Fatalf("Handle(ApproveDevice): %v", res.Err)
	}
	if res.ChangeID == "" {
		t.Error("successful command must carry a ChangeID")
	}
	if len(ap.rulesets) != 1 {
		t.Fatalf("applier saw %d rulesets, want 1", len(ap.rulesets))
	}
	out := string(ap.rulesets[0])
	if !strings.Contains(out, "aa:bb:cc:dd:00:0a : 0x02") {
		t.Errorf("ruleset missing mac_zone element for the approved device:\n%s", out)
	}
}

func TestAuthorizeAndRevokeGuest(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	ctx := context.Background()

	if res := h.Handle(ctx, core.AuthorizeGuest{MAC: "aa:bb:cc:dd:00:0b", TTL: time.Hour}); res.Err != nil {
		t.Fatalf("Handle(AuthorizeGuest): %v", res.Err)
	}
	out := string(ap.rulesets[len(ap.rulesets)-1])
	if !strings.Contains(out, "aa:bb:cc:dd:00:0b timeout ") {
		t.Errorf("authed_guests missing the new guest with a timeout:\n%s", out)
	}

	if res := h.Handle(ctx, core.RevokeGuest{MAC: "aa:bb:cc:dd:00:0b"}); res.Err != nil {
		t.Fatalf("Handle(RevokeGuest): %v", res.Err)
	}
	out = string(ap.rulesets[len(ap.rulesets)-1])
	if strings.Contains(out, "aa:bb:cc:dd:00:0b") {
		t.Errorf("revoked guest still present in authed_guests:\n%s", out)
	}
}

func TestCommandErrorStillReconcilesNothing(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	ctx := context.Background()

	// Approving into a nonexistent zone fails in the store: no ruleset
	// may be rendered or applied afterwards.
	res := h.Handle(ctx, core.ApproveDevice{MAC: "aa:bb:cc:dd:00:0c", ZoneID: 42})
	if res.Err == nil {
		t.Fatal("approve into unknown zone must fail")
	}
	if len(ap.rulesets) != 0 {
		t.Errorf("applier saw %d rulesets after a failed mutation, want 0", len(ap.rulesets))
	}
}

func TestSetupModeOmitsDeviceState(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	h.Setup = true // DD-15
	ctx := context.Background()

	if res := h.Handle(ctx, core.ApproveDevice{MAC: "aa:bb:cc:dd:00:0d", ZoneID: 2}); res.Err != nil {
		t.Fatalf("Handle in setup mode: %v", res.Err)
	}
	out := string(ap.rulesets[len(ap.rulesets)-1])
	if strings.Contains(out, "aa:bb:cc:dd:00:0d") {
		t.Error("setup mode must not render device-derived state (DD-15)")
	}
	if !strings.Contains(out, `iifname "br-lan" meta mark set 0x01`) {
		t.Error("setup mode must classify br-lan as the admin plane")
	}
}

func TestRejectedRulesetMapsToConfigRejected(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	ap.fail = &nft.CheckError{Path: "kcp.nft", Output: "syntax error line 42"} // real type, so errors.As hits
	ctx := context.Background()

	res := h.Handle(ctx, core.AuthorizeGuest{MAC: "aa:bb:cc:dd:00:0e", TTL: time.Minute})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "config.rejected") {
		t.Fatalf("rejected ruleset must surface config.rejected, got %v", res.Err)
	}
	// The mutation itself already committed: state.db stays the source of
	// truth and the re-apply loop converges later.
	snap, err := store.LoadPlan(h.DB, h.Now())
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if len(snap.Guests) != 1 {
		t.Errorf("guest session lost after ruleset rejection — state.db must not roll back")
	}
}

func TestSyncReappliesWithoutCommand(t *testing.T) {
	h, ap, _ := newTestHandler(t)
	ctx := context.Background()

	if err := h.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(ap.rulesets) != 1 {
		t.Fatalf("Sync produced %d rulesets, want 1", len(ap.rulesets))
	}
	// Startup output with an empty db must still be a complete ruleset:
	// all five kcp tables present, Waiting quarantined.
	out := string(ap.rulesets[0])
	for _, want := range []string{"table inet kcp_zones", "table inet kcp_portal", "table inet kcp_filter", "table ip kcp_nat", "table bridge kcp_l2"} {
		if !strings.Contains(out, want) {
			t.Errorf("startup ruleset missing %s", want)
		}
	}
}

// DD-14: appEgressAllows converts tcp printer entries into nft allows,
// skipping usb-mode apps and hostname addresses (IP literals only —
// the container has no resolver).
func TestAppEgressAllows(t *testing.T) {
	cfg := config.Default()
	cfg.AppsUID = 1001
	cfg.Apps = []config.AppEntry{
		{ID: "pos-cafe", PrinterMode: "tcp", PrinterAddr: "10.20.2.20:9100"},
		{ID: "pos-usb", PrinterMode: "usb", PrinterAddr: "/dev/usb/lp0"},
		{ID: "pos-host", PrinterMode: "tcp", PrinterAddr: "printer.local:9100"}, // hostname: skipped
		{ID: "pos-bad", PrinterMode: "tcp", PrinterAddr: "10.20.2.99:notaport"},
	}
	h := NewHandler(nil, cfg, &stubApplier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	allows := h.appEgressAllows()
	if len(allows) != 1 || allows[0].DstIP != "10.20.2.20" || allows[0].Proto != "tcp" || allows[0].Port != 9100 {
		t.Fatalf("allows = %+v", allows)
	}
}
