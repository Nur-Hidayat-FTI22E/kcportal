package portaledge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/netctl"
	"kotacloud-portal/internal/portal"
	"kotacloud-portal/internal/reconcile"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/store/storetest"
)

type stubApplier struct{}

func (stubApplier) Apply(context.Context, []byte) (string, error) { return "stub", nil }

type fixture struct {
	srv   *Server
	mock  *netctl.Mock
	actor *core.Actor
	db    interface{ Close() error }
	h     http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := storetest.Open(t)
	if err := store.EnsureSeedZones(db, []store.SeedZone{
		{ID: 1, Name: "admin", Subnet: "10.20.1.0/24", Internet: true},
	}); err != nil {
		t.Fatal(err)
	}
	mock := netctl.NewMock()
	actor := core.NewActor(core.NewBus(16), reconcile.NewHandler(db, config.Default(), stubApplier{}, slog.Default()).Handle)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go actor.Run(ctx)
	ps := portal.New("kunci-pemasaran")
	srv := New(Config{Addr: ":0", TTL: time.Hour}, db, mock, actor, ps, slog.Default())
	return &fixture{srv: srv, mock: mock, actor: actor, db: db, h: srv.srv.Handler}
}

// ensureGuestDevice mirrors production: the guest joined, dnsmasq handed
// out a lease, and the dhcp-hook watcher upserted devices + ip_leases —
// the rows portal.View reads.
func (f *fixture) ensureGuestDevice(t *testing.T) {
	t.Helper()
	now := time.Now()
	if _, err := store.UpsertSeenDevice(f.srv.DB, guestMAC.String(), "hp-tamu", "br-guest", now); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertLease(f.srv.DB, guestMAC.String(), guestIP, 2*time.Hour, now); err != nil {
		t.Fatal(err)
	}
}

// postForm talks to the handler as a guest at clientIP.
func (f *fixture) postForm(t *testing.T, clientIP, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.RemoteAddr = clientIP + ":44444"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec.Result()
}

func (f *fixture) get(t *testing.T, clientIP, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = clientIP + ":44444"
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec.Result()
}

const guestIP = "10.20.3.44"

var guestMAC = mustMAC("aa:bb:cc:dd:21:44")

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// Without a neighbor entry the portal refuses to identify the client —
// DD-10: no kernel table entry, no service.
func TestUnknownClientForbidden(t *testing.T) {
	f := newFixture(t)
	resp := f.get(t, guestIP, "/state")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown client -> %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "identitas") {
		t.Fatalf("body = %s", body)
	}
}

// The full consent flow: terms+marketing → session row with consent
// metadata → /state flips to authorized. This is the FR-CPT-002 path.
func TestConsentFlowAuthorizesGuest(t *testing.T) {
	f := newFixture(t)
	ip := netip.MustParseAddr(guestIP)
	f.mock.SeedNeighbor("br-guest", ip, guestMAC)
	f.mock.SeedBinding(guestMAC, ip)
	f.ensureGuestDevice(t)

	// Missing terms consent must fail.
	resp := f.postForm(t, guestIP, "marketing=yes&name=Budi")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no-terms -> %d, want 400", resp.StatusCode)
	}

	// Proper consent: marketing with name+contact.
	resp = f.postForm(t, guestIP, "terms=yes&marketing=yes&name=Budi&contact=budi@x.id")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent -> %d, want 303: %s", resp.StatusCode, statusText(resp))
	}

	// The read model shows an authorized marketing-consented session —
	// the DB rows ARE the kernel truth (reconcile renders authed_guests
	// from them; the Mock map is only the legacy broker stand-in).
	view, err := portal.View(f.srv.DB, guestMAC.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !view.Authorized || !view.Marketing || view.TTL <= 0 {
		t.Fatalf("view = %+v", view)
	}

	// /state for the guest reports authorized.
	resp = f.get(t, guestIP, "/state")
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("/state = %s", body)
	}
}

// Voucher path: a valid code opens a session with the voucher's
// duration; an exhausted/unknown code fails without opening one.
func TestVoucherRedemption(t *testing.T) {
	f := newFixture(t)
	ip := netip.MustParseAddr(guestIP)
	f.mock.SeedNeighbor("br-guest", ip, guestMAC)
	f.mock.SeedBinding(guestMAC, ip)
	f.ensureGuestDevice(t)
	if err := store.CreateVouchers(f.srv.DB, []string{"TESTVCH25"}, 90*time.Minute, 1, time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Bad code: 409 with a friendly message, no session.
	resp := f.postForm(t, guestIP, "terms=yes&voucher=NOPE1")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("bad voucher -> %d, want 409", resp.StatusCode)
	}
	if v, err := portal.View(f.srv.DB, guestMAC.String(), time.Now()); err != nil || v.Authorized {
		t.Fatalf("bad voucher must not authorize: %+v err=%v", v, err)
	}

	// Good code: authorized.
	resp = f.postForm(t, guestIP, "terms=yes&voucher=testvch25") // case-insensitive
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("voucher -> %d: %s", resp.StatusCode, statusText(resp))
	}
	view, err := portal.View(f.srv.DB, guestMAC.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !view.Authorized || view.TTL > 91*time.Minute {
		t.Fatalf("voucher TTL not applied: %+v", view)
	}
}

// A second redemption of a max_uses=1 voucher must fail (atomic guard).
func TestVoucherSingleUse(t *testing.T) {
	f := newFixture(t)
	ip := netip.MustParseAddr(guestIP)
	f.mock.SeedNeighbor("br-guest", ip, guestMAC)
	f.mock.SeedBinding(guestMAC, ip)
	f.ensureGuestDevice(t)
	if err := store.CreateVouchers(f.srv.DB, []string{"ONEUSE1"}, time.Hour, 1, time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp := f.postForm(t, guestIP, "terms=yes&voucher=ONEUSE1"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first redeem -> %d: %s", resp.StatusCode, statusText(resp))
	}
	if resp := f.postForm(t, guestIP, "terms=yes&voucher=ONEUSE1"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("second redeem -> %d, want 409 (exhausted)", resp.StatusCode)
	}
}

func statusText(resp *http.Response) string {
	if resp == nil {
		return "<nil>"
	}
	b := make([]byte, 200)
	n, _ := resp.Body.Read(b)
	return resp.Status + " " + string(b[:n])
}
