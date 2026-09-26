// kcportald is the single process described in §2.5: supervisor, state
// actor, event bus, watchers, listeners, workers. M0 wires only the parts
// that don't yet need real nft/hostapd/dnsmasq access, so this binary is
// runnable today with -dev on any Linux dev machine — no Pi, no root.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/net/netctl"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/supervisor"
)

func main() {
	cfgPath := flag.String("config", "/etc/kcportal/app.yaml", "path to app.yaml")
	statePath := flag.String("state", "/data/kcportal/state.db", "path to state.db")
	devMode := flag.Bool("dev", false, "use an in-memory NetCtl mock instead of real nft/netlink (no root or Pi required)")
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

	bus := core.NewBus(64)
	actor := core.NewActor(bus, nil) // real handler (state mutation + reconciler Plan) lands in M1

	var nc netctl.NetCtl
	if *devMode {
		nc = netctl.NewMock()
		log.Warn("using the in-memory NetCtl mock — nothing here touches nft, hostapd, or dnsmasq (-dev)")
	} else {
		log.Error("real NetCtl (nft + netlink) is not implemented yet (arrives M1/M2) — run with -dev on a non-Pi dev machine")
		os.Exit(1)
	}
	_ = nc // wired into portal-edge starting at M3

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

	log.Info("kcportald M0 skeleton running — Ctrl-C to stop")
	sup.Run(ctx)
	log.Info("shutdown complete")
}
