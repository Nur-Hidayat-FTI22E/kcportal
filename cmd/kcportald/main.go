// kcportald is the single process described in §2.5: supervisor, state
// actor, event bus, watchers, listeners, workers. M1 wires the real
// reconciler: commands mutate state.db, the handler rebuilds the Plan
// and pushes it to nftables (still with -dev as a no-kernel dry run —
// the real NetCtl for hostapd/dnsmasq arrives in M2).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/netctl"
	"kotacloud-portal/internal/net/nft"
	"kotacloud-portal/internal/reconcile"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/supervisor"
)

func main() {
	cfgPath := flag.String("config", "/etc/kcportal/app.yaml", "path to app.yaml")
	statePath := flag.String("state", "/data/kcportal/state.db", "path to state.db")
	nftDir := flag.String("nft-dir", "/run/kcportal", "directory for the generated kcp.nft (tmpfs, PD-4)")
	devMode := flag.Bool("dev", false, "dry-run nft (no kernel ruleset) and use the in-memory NetCtl mock — no root or Pi required")
	setupMode := flag.Bool("setup", false, "DD-15 setup mode: br-lan is the admin plane, device state is not applied")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Warn("no usable app.yaml yet — falling back to Café MVP defaults (DD-15 setup mode)",
			"path", *cfgPath, "err", err)
		cfg = config.Default()
	}
	log.Info("config loaded", "profile", cfg.Profile, "wan_mode", cfg.WAN.Mode, "zones", len(cfg.Zones))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.Open(ctx, *statePath)
	if err != nil {
		log.Error("cannot open state.db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Seed/update the zone rows from config (idempotent upsert, boot-time
	// only — the Actor never writes zones).
	seeds := make([]store.SeedZone, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		if z.ID <= 0 {
			continue // waiting (mark 0x00) is virtual — devices.state, not a row
		}
		seeds = append(seeds, store.SeedZone{ID: z.ID, Name: z.Name, Subnet: z.Subnet, Internet: z.Internet})
	}
	if err := store.EnsureSeedZones(db, seeds); err != nil {
		log.Error("cannot seed zones", "err", err)
		os.Exit(1)
	}

	bus := core.NewBus(64)

	// The reconciler: state.db -> Plan -> nft -c/-f (§4.3). In dev mode
	// the applier validates but skips the kernel install; on a real Pi it
	// runs fail-closed against the live ruleset.
	applier := &nft.Applier{Dir: *nftDir, DryRun: *devMode}
	handler := reconcile.NewHandler(db, cfg, applier, log)
	handler.Setup = *setupMode || cfg.Profile != "cafe" // unknown profiles ride setup mode until configured
	actor := core.NewActor(bus, handler.Handle)

	var nc netctl.NetCtl
	if *devMode {
		nc = netctl.NewMock()
		log.Warn("using the in-memory NetCtl mock — nothing here touches nft, hostapd, or dnsmasq (-dev)")
	} else {
		nc = nil // real NetCtl (netlink + hostapd ctrl) lands in M2
		log.Warn("NetCtl not wired yet (arrives M2) — portal data-plane listeners are not running")
	}
	_ = nc

	sup := supervisor.New(log)
	sup.Add("state-actor", actor.Run)
	sup.Add("event-logger", func(ctx context.Context) {
		ch, unsub := bus.Subscribe()
		defer unsub()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				log.Info("event", "type", ev.Type)
			}
		}
	})
	sup.Add("drift-reapply", func(ctx context.Context) {
		// §4.3 notes: every 30s the desired state is re-applied so manual
		// nft tampering or a lost install converges. Sync is idempotent
		// and cheap (one SQLite read + one nft -c/-f round trip).
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := handler.Sync(ctx); err != nil {
					log.Warn("periodic re-apply failed (will retry)", "err", err)
				}
			}
		}
	})

	// Bring the ruleset up before announcing readiness: commands are
	// accepted only after the first reconcile has run.
	if err := handler.Sync(ctx); err != nil {
		log.Error("initial ruleset apply failed", "err", err)
		os.Exit(1)
	}
	log.Info("kcportald M1 running — reconciler active, Ctrl-C to stop")
	sup.Run(ctx)
	log.Info("shutdown complete")
}
