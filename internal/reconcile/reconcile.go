// Package reconcile implements the state actor's real M1 Handler: every
// Command is applied to state.db first, then the resulting desired state
// is rendered and applied to nftables — the §4.3 "state.db -> Plan ->
// transaksi nft" pipeline, with PD-3's single-writer discipline intact
// (the Handler runs on the actor goroutine only).
package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/confirm"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/nft"
	"kotacloud-portal/internal/store"
)

// Applier is what the reconciler needs from the nftables side: the
// nft.Applier satisfies it (a stub stands in for tests).
type Applier interface {
	Apply(ctx context.Context, ruleset []byte) (string, error)
}

// Handler is the real M1 command handler wired into core.NewActor.
type Handler struct {
	DB    *sql.DB
	Cfg   *config.Config
	Apply Applier // the nft.Applier, or a test stub
	Log   *slog.Logger
	Now   func() time.Time // injectable clock for tests
	Setup bool             // DD-15 setup mode: the mgmt plane is admin, no mac_zone entries
	// SetupMgmtIface names the setup-mode management plane stamped 0x01
	// by classify (lab: eth0 keeps SSH alive; production default br-lan).
	SetupMgmtIface string
	Confirm        *confirm.Manager // commit-confirm for risky changes (ADR-006); nil = no risky handling

	// NeighRev, when wired (cmd/kcportald), increments on every
	// successful ruleset apply; main.go's netlink subscription bumps the
	// same counter on RTM_NEWNEIGH pushes, so downstream (the M3 Bouncer,
	// cache busting) can tell "the ruleset moved" from "nothing
	// happened". PD-4: derived state — deliberately RAM-only.
	NeighRev *atomic.Uint64

	lastGood []byte // last successfully applied ruleset — the snapshot source
}

// NewHandler builds a Handler; applier may be nil when the caller wires
// it right after (cmd/kcportald) — Handle reports a clear error until
// one is set.
func NewHandler(db *sql.DB, cfg *config.Config, applier Applier, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{DB: db, Cfg: cfg, Apply: applier, Log: log, Now: time.Now}
}

// Handle implements core.Handler: mutate state.db, rebuild the Plan,
// render, apply. A failed nft apply does NOT roll back the state.db
// mutation — state.db is the source of truth (§4.3); the periodic
// re-apply loop converges the kernel once the failure clears. Fail-closed
// (NFR-REL-04) means the OLD ruleset keeps running meanwhile.
//
// Risky commands (ADR-006: anything that can strand the admin — zone
// policy on the admin's own zone, WAN mode) additionally start a
// commit-confirm trial: the change goes live but Result.Deadline is set
// (IF-02), and the confirm.Manager rolls back to the last-good snapshot
// unless the admin confirms in time.
func (h *Handler) Handle(ctx context.Context, cmd core.Command) core.Result {
	if h.Apply == nil {
		return core.Result{Err: fmt.Errorf("reconcile: no applier wired (bug: handler not initialised)")}
	}
	if err := h.applyCommand(cmd); err != nil {
		h.Log.Error("command failed", "cmd", cmd.Name(), "err", err)
		return core.Result{Err: err}
	}

	path, err := h.reconcile(ctx)
	if err != nil {
		var ce *nft.CheckError
		if errors.As(err, &ce) {
			// The ruleset was rejected by nft -c: a config/plan bug. The
			// previous ruleset still runs; surface the NFR-REL-04 mapping
			// so the bus event layer can emit config.rejected.
			h.Log.Error("ruleset rejected — previous ruleset kept", "err", err)
			return core.Result{Err: fmt.Errorf("config.rejected: %w", err)}
		}
		h.Log.Error("ruleset apply failed — re-apply loop will retry", "cmd", cmd.Name(), "err", err)
		return core.Result{Err: err}
	}

	changeID := fmt.Sprintf("%s@%d", cmd.Name(), h.Now().Unix())
	h.Log.Info("ruleset applied", "cmd", cmd.Name(), "path", path)

	// ADR-006: risky changes ride the confirm window before they are
	// trusted. The Deadline in the Result is what the GUI shows.
	if reason, risky := h.risky(cmd); risky && h.Confirm != nil {
		deadline, cerr := h.Confirm.Begin(ctx, changeID, reason, h.lastGood)
		if cerr != nil {
			return core.Result{Err: fmt.Errorf("reconcile: confirm begin: %w", cerr)}
		}
		return core.Result{ChangeID: changeID, Deadline: deadline}
	}
	return core.Result{ChangeID: changeID}
}

// risky implements the ADR-006 list: changes able to strand the admin
// who requested them. M1: zone policy (its forward rules can cut the
// admin's own zone off the mgmt listener). WAN mode and Wi-Fi
// band/SSID arrive with their milestones and join this list.
func (h *Handler) risky(cmd core.Command) (string, bool) {
	switch c := cmd.(type) {
	case core.PutZonePolicy:
		if c.ZoneID == 1 { // the Admin zone carries the mgmt listener (§2.4)
			return "zone policy change on the Admin zone (mgmt listener reachability)", true
		}
		return "", false
	default:
		return "", false
	}
}

// Sync re-applies desired state without a command — the startup path and
// the body of the periodic drift re-apply loop.
func (h *Handler) Sync(ctx context.Context) error {
	if h.Apply == nil {
		return fmt.Errorf("reconcile: no applier wired (bug: handler not initialised)")
	}
	_, err := h.reconcile(ctx)
	return err
}

// applyCommand mutates state.db for the supported commands (single
// writer, PD-3: only this method ever writes device/session rows).
func (h *Handler) applyCommand(cmd core.Command) error {
	now := h.Now()
	switch c := cmd.(type) {
	case core.ApproveDevice:
		return store.ApproveDevice(h.DB, c.MAC, c.ZoneID, c.Note, "admin", now)
	case core.RevokeGuest:
		return store.CloseGuestSessions(h.DB, c.MAC, now) // authed_guests drops the MAC on the next Plan build
	case core.AuthorizeGuest:
		// M3 portal path: carry the consent record into guest_sessions
		// (FR-CPT-002) in the same single-writer step; empty metadata
		// fields keep the M2 call sites (ops CLI, tests) byte-identical.
		ttl := c.TTL
		if c.Voucher != "" {
			// Voucher consumption is part of the same writer step: its
			// duration replaces TTL and a bad code fails the command
			// (the portal maps store.ErrNotFound to a 4xx message).
			dur, err := store.RedeemVoucher(h.DB, c.Voucher, now)
			if err != nil {
				return err
			}
			ttl = dur
		}
		if c.SessionID == "" && !c.Marketing && c.TenantID == "" && c.Terms == "" {
			return store.StartGuestSession(h.DB, c.MAC, ttl, now)
		}
		return store.StartGuestSessionWithMeta(h.DB, store.SessionMeta{
			MAC:        c.MAC,
			SessionID:  c.SessionID,
			TenantID:   c.TenantID,
			Marketing:  c.Marketing,
			Payload:    c.Payload,
			Terms:      c.Terms,
			Lang:       c.Lang,
			Expiration: now.Add(ttl),
		}, now)
	case core.PutZonePolicy:
		// M1: the policy columns live in state.db (§8 zones), so the
		// write path exists even though the REST admin (M3) is what will
		// call it through the GUI.
		allows := make([]store.LANAllow, 0, len(c.LANAllow))
		for _, a := range c.LANAllow {
			allows = append(allows, store.LANAllow{DstIP: a.DstIP, Proto: a.Proto, Port: a.Port})
		}
		return store.PutZonePolicy(h.DB, c.ZoneID, c.Internet, c.VPNRequired, allows, "admin", now)
	default:
		return fmt.Errorf("reconcile: no state mutation wired for %s yet", cmd.Name())
	}
}

// reconcile rebuilds desired state from state.db and pushes it to
// nftables. Shared by Sync (startup / drift loop) and every command.
func (h *Handler) reconcile(ctx context.Context) (string, error) {
	snap, err := store.LoadPlan(h.DB, h.Now())
	if err != nil {
		return "", fmt.Errorf("reconcile: load plan: %w", err)
	}
	plan, err := h.buildPlan(snap)
	if err != nil {
		return "", fmt.Errorf("reconcile: build plan: %w", err)
	}
	ruleset, err := nft.Render(plan)
	if err != nil {
		return "", fmt.Errorf("reconcile: render: %w", err)
	}

	sum := sha256.Sum256(ruleset)
	if err := store.SetSetting(h.DB, "ruleset_sha256", fmt.Sprintf("%x", sum[:])); err != nil {
		return "", fmt.Errorf("reconcile: record ruleset hash: %w", err)
	}

	path, err := h.Apply.Apply(ctx, ruleset)
	if err != nil {
		return path, err // pass *nft.CheckError through untouched for errors.As
	}
	h.lastGood = append(h.lastGood[:0], ruleset...) // snapshot source for commit-confirm
	if h.NeighRev != nil {
		h.NeighRev.Add(1)
	}
	return path, nil
}

// buildPlan converts the store snapshot into an nft.Plan. Zone policy
// (subnets already live in state.db, lan_allow still in config until the
// M3 REST admin writes it to state.db); bridges/addresses follow §2.4.
func (h *Handler) buildPlan(snap *store.Plan) (*nft.Plan, error) {
	zones := make([]nft.Zone, 0, len(snap.Zones))
	zoneMark := map[int]uint32{}
	for _, z := range snap.Zones {
		mark := uint32(z.ID) // zones table has no mark column yet; §2.4 keeps id == mark for the Café profile
		zoneMark[z.ID] = mark
		nz := nft.Zone{
			ID:       z.ID,
			Name:     z.Name,
			Mark:     mark,
			Internet: z.Internet,
			VPN:      z.VPN == "required",
			LANAllow: h.lanAllowsFor(z.ID),
		}
		// DB-stored lan_allow (PutZonePolicy) wins over config; config is
		// only the boot default until the M3 admin writes the row.
		if len(z.LANAllow) > 0 {
			nz.LANAllow = nil
			for _, a := range z.LANAllow {
				nz.LANAllow = append(nz.LANAllow, nft.LANAllow{DstIP: a.DstIP, Proto: a.Proto, Port: uint16(a.Port)})
			}
		}
		zones = append(zones, nz)
	}

	plan := &nft.Plan{
		Now:            h.Now(), // one clock for expiry math across the pipeline
		SetupMode:      h.Setup,
		SetupMgmtIface: h.SetupMgmtIface,
		MgmtV4:         h.mgmtV4(),
		Uplinks:        h.uplinks(),
		Zones:          zones,
		GuestBridge:    "br-guest", // DD-01 fixed pairing
		LANBridge:      "br-lan",
		GuestPortal:    "10.20.3.1:8080",  // §2.4 portal-edge listener
		WaitingDNSStub: "10.20.99.1:5354", // ERR-01 stub REFUSED
		WaitingHTTP:    "10.20.99.1:8081", // ERR-01 info page
		GuestUpKbps:    h.Cfg.Portal.UplinkKbps,
		GuestDownKbps:  h.Cfg.Portal.DownlinkKbps,
	}

	if !h.Setup { // DD-15: no device-derived identity state in setup mode
		for _, d := range snap.Devices {
			if d.Expires != nil && d.Expires.Before(h.Now()) {
				continue // expired approval drops out until the M1 watcher flips devices.state
			}
			mark, ok := zoneMark[d.ZoneID]
			if !ok {
				return nil, fmt.Errorf("device %s references zone %d missing from zones table", d.MAC, d.ZoneID)
			}
			plan.MACZones = append(plan.MACZones, nft.MACZone{MAC: d.MAC, ZoneID: d.ZoneID, ZoneMark: mark})
		}
		for _, l := range snap.Bindings {
			var expires time.Time
			if l.Expires != nil {
				expires = *l.Expires
			}
			plan.Bindings = append(plan.Bindings, nft.Binding{MAC: l.MAC, IP: l.IP, Expires: expires})
		}
	}
	// Guest sessions render in EVERY posture: they are the portal's own
	// runtime authorization (granted explicitly via the actor), not
	// learned identity — DD-15's setup mode skips mac_zone/bindings, but
	// the authed_guests path must stay testable end-to-end while the
	// lab runs -setup (observed: sessions granted but the set stayed
	// empty, breaking the whole approve flow).
	for _, g := range snap.Guests {
		plan.Guests = append(plan.Guests, nft.Guest{MAC: g.MAC, Expires: g.ExpiresAt})
	}
	return plan, nil
}

// mgmtV4 derives the management subnet (first IPv4 addr of the setup
// mgmt iface, as a /24) for the anti-lockout input rule. KCP_MGMT_V4
// overrides (e.g. "192.168.100.0/24"); empty disables the rule. The
// rule is only emitted when an explicit mgmt iface is configured —
// DD-15's posture is exactly the lab case needing it.
func (h *Handler) mgmtV4() string {
	if env := os.Getenv("KCP_MGMT_V4"); env != "" {
		return strings.TrimSpace(env)
	}
	if h.SetupMgmtIface == "" {
		return ""
	}
	ifc, err := net.InterfaceByName(h.SetupMgmtIface)
	if err != nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			netIP := ipn.IP.To4().Mask(net.CIDRMask(24, 32)) // the SUBNET, not the host addr
			return fmt.Sprintf("%s/24", netIP.String())
		}
	}
	return ""
}

// lanAllowsFor resolves zone lan_allow from config by zone id (config is
// the policy source; the M3 admin will move this into state.db).
func (h *Handler) lanAllowsFor(zoneID int) []nft.LANAllow {
	var out []nft.LANAllow
	for _, z := range h.Cfg.Zones {
		if z.ID != zoneID {
			continue
		}
		for _, a := range z.LANAllow {
			out = append(out, nft.LANAllow{DstIP: a.DstIP, Proto: a.Proto, Port: uint16(a.Port)})
		}
	}
	return out
}

// uplinks derives the egress interfaces from the WAN mode (§4.1):
// pppoe rides ppp0, dhcp/static ride the ethernet uplink wan0. VPN
// tunnels arrive with the VPN milestone; the kill-switch sets simply
// stay empty until then.
func (h *Handler) uplinks() nft.Uplinks {
	// KCP_WAN_IFACE overrides the §4.1 derivation (comma-separated): the
	// lab Pi rides its eth0 as the uplink while wan0 does not exist —
	// without this the forward-accept/masquerade rules target an
	// interface that will never carry traffic (observed E2E: guests got
	// DHCP + captive page but no internet).
	if env := strings.TrimSpace(os.Getenv("KCP_WAN_IFACE")); env != "" {
		parts := strings.Split(env, ",")
		wans := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				wans = append(wans, p)
			}
		}
		if len(wans) > 0 {
			return nft.Uplinks{WAN: wans}
		}
	}
	switch h.Cfg.WAN.Mode {
	case "pppoe":
		return nft.Uplinks{WAN: []string{"ppp0"}}
	default:
		return nft.Uplinks{WAN: []string{"wan0"}}
	}
}
