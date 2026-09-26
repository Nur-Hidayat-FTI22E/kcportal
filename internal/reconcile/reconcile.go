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
	"time"

	"kotacloud-portal/internal/config"
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
	Setup bool             // DD-15 setup mode: br-lan is the admin plane, no mac_zone entries
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

	h.Log.Info("ruleset applied", "cmd", cmd.Name(), "path", path)
	return core.Result{ChangeID: fmt.Sprintf("%s@%d", cmd.Name(), h.Now().Unix())}
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
		return store.StartGuestSession(h.DB, c.MAC, c.TTL, now)
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
			LANAllow: h.lanAllowsFor(z.ID),
		}
		zones = append(zones, nz)
	}

	plan := &nft.Plan{
		Now:            h.Now(), // one clock for expiry math across the pipeline
		SetupMode:      h.Setup,
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

	if !h.Setup { // DD-15: no device-derived state in setup mode
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
		for _, g := range snap.Guests {
			plan.Guests = append(plan.Guests, nft.Guest{MAC: g.MAC, Expires: g.ExpiresAt})
		}
		for _, l := range snap.Bindings {
			var expires time.Time
			if l.Expires != nil {
				expires = *l.Expires
			}
			plan.Bindings = append(plan.Bindings, nft.Binding{MAC: l.MAC, IP: l.IP, Expires: expires})
		}
	}
	return plan, nil
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
	switch h.Cfg.WAN.Mode {
	case "pppoe":
		return nft.Uplinks{WAN: []string{"ppp0"}}
	default:
		return nft.Uplinks{WAN: []string{"wan0"}}
	}
}
