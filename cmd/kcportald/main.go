// kcportald is the single process described in §2.5: supervisor, state
// actor, event bus, watchers, listeners, workers. M1 wires the real
// reconciler: commands mutate state.db, the handler rebuilds the Plan
// and pushes it to nftables (still with -dev as a no-kernel dry run —
// the real NetCtl for hostapd/dnsmasq arrives in M2).
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sync/atomic"

	"kotacloud-portal/internal/api"
	"kotacloud-portal/internal/config"
	"kotacloud-portal/internal/confirm"
	"kotacloud-portal/internal/core"
	"kotacloud-portal/internal/listen/portaledge"
	"kotacloud-portal/internal/listen/waitingdns"
	"kotacloud-portal/internal/listen/waitinghttp"
	"kotacloud-portal/internal/net/dhcp"
	"kotacloud-portal/internal/net/netctl"
	"kotacloud-portal/internal/net/netlink"
	"kotacloud-portal/internal/net/nft"
	"kotacloud-portal/internal/net/wifi/hostapdctl"
	"kotacloud-portal/internal/portal"
	"kotacloud-portal/internal/reconcile"
	"kotacloud-portal/internal/runtimecfg"
	"kotacloud-portal/internal/store"
	"kotacloud-portal/internal/supervisor"
	"kotacloud-portal/internal/watchers/dhcphook"
	"kotacloud-portal/internal/watchers/neighbors"
)

func main() {
	cfgPath := flag.String("config", "/etc/kcportal/app.yaml", "path to app.yaml")
	statePath := flag.String("state", "/data/kcportal/state.db", "path to state.db")
	nftDir := flag.String("nft-dir", "/run/kcportal", "directory for the generated kcp.nft (tmpfs, PD-4)")
	devMode := flag.Bool("dev", false, "dry-run nft (no kernel ruleset) and use the in-memory NetCtl mock — no root or Pi required")
	setupMode := flag.Bool("setup", false, "DD-15 setup mode: br-lan is the admin plane, device state is not applied")
	mgmtIface := flag.String("mgmt-iface", "", "setup-mode management plane stamped 0x01 by classify (e.g. eth0 during lab deployment; empty = br-lan default). Setting it implies -setup posture")
	approveMAC := flag.String("approve", "", "ops utility: grant a 60-minute guest session for this MAC (state.db write; the running daemon applies it within 30 s)")
	revokeMAC := flag.String("revoke", "", "ops utility: close all guest sessions for this MAC")
	neighDump := flag.Bool("neigh-dump", false, "dump the kernel neighbor table via rtnetlink and exit (ops/debug utility)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8083", "REST admin API listen address (§7.2; keep on the mgmt plane/loopback)")
	printAPIToken := flag.Bool("api-token", false, "ops utility: print the admin API token (generated on first boot) and continue serving")
	flag.Parse()

	// Ops utilities that only touch state.db and exit (the actor's own
	// write paths, so PD-3 semantics hold).
	if *approveMAC != "" || *revokeMAC != "" {
		raw := *approveMAC
		action := "session granted"
		if raw == "" {
			raw = *revokeMAC
			action = "sessions closed"
		}
		mac, perr := net.ParseMAC(raw)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "bad MAC %q: %v\n", raw, perr)
			os.Exit(1)
		}
		db, err := store.Open(context.Background(), *statePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", *statePath, err)
			os.Exit(1)
		}
		defer db.Close()
		now := time.Now()
		var opErr error
		if *approveMAC != "" {
			opErr = store.StartGuestSession(db, mac.String(), 60*time.Minute, now)
		} else {
			opErr = store.CloseGuestSessions(db, mac.String(), now)
		}
		if opErr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", action, opErr)
			os.Exit(1)
		}
		fmt.Printf("%s for %s (authed_guests follows on the next reconcile)\n", action, mac.String())
		// §4.6 effect ordering, ops edition: the kernel side is done
		// (state.db closed the session above; the running daemon re-renders
		// the ruleset within its 30 s cadence), so the radio kick follows.
		// Revoke only: an approval does not deauth anyone. Best-effort —
		// hostapd may not be running (dev box, radio down); nft stands.
		if *revokeMAC != "" {
			bssList := []string{radioIface()}
			if os.Getenv("KCP_WIFI_BSS") != "single" {
				bssList = append(bssList, radioIface()+"_1")
			}
			if err := hostapdctl.OneshotDeauthenticate("/run/kcportal/hostapd", bssList, mac.String()); err != nil {
				fmt.Fprintf(os.Stderr, "radio deauth failed (kernel revoke stands; hostapd down?): %v\n", err)
			}
		}
		return
	}

	if *neighDump {
		rows, err := netlink.New().Dump()
		if err != nil {
			fmt.Fprintf(os.Stderr, "neigh-dump: %v\n", err)
			os.Exit(1)
		}
		for _, r := range rows {
			fmt.Printf("%-40s %-17s %-12s nud=0x%04x\n", r.IP.String(), r.MAC, r.Iface, r.State)
		}
		fmt.Printf("# %d usable entries\n", len(rows))
		return
	}

	// Ops: mint/print the admin API token, then continue into normal
	// serving (the token is also loaded again inside main's wiring).
	if *printAPIToken {
		probe, err := store.Open(context.Background(), *statePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", *statePath, err)
			os.Exit(1)
		}
		tok, created, err := api.LoadToken(probe)
		_ = probe.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "api-token: %v\n", err)
			os.Exit(1)
		}
		_ = created // first call creates + stores it; printing is the point
		fmt.Printf("api-token: %s\n", tok)
		// Print-and-exit: the running daemon serves the API; a second
		// full instance here would race it for the ruleset.
		return
	}

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
	handler.SetupMgmtIface = *mgmtIface
	if *mgmtIface != "" {
		handler.Setup = true // an explicit mgmt plane IS the DD-15 setup posture
	}

	// Commit-confirm (§4.7 ADR-006): risky changes get a 60 s trial; the
	// boot path rolls back any pending.json orphaned by a crash BEFORE
	// the daemon serves anything.
	confirmer := confirm.NewManager(*nftDir, func(ctx context.Context, ruleset []byte) error {
		_, err := applier.Apply(ctx, ruleset)
		return err
	}, log)
	handler.Confirm = confirmer
	if recovered, err := confirmer.Recover(ctx); err != nil {
		log.Error("pending change rollback failed — refusing to serve", "err", err)
		os.Exit(1)
	} else if recovered {
		log.Warn("unconfirmed risky change rolled back to last-good ruleset (crash recovery)")
	}

	actor := core.NewActor(bus, handler.Handle)

	// The netlink revision counter: bumped by every successful ruleset
	// apply and by the RTM_NEWNEIGH subscription below — the "something
	// moved on the wire" signal (PD-4, RAM-only).
	neighRev := new(atomic.Uint64)
	handler.NeighRev = neighRev

	// Broker for IF-01: guest authorize/revoke goes through the state
	// actor (§7.3 — authed_guests never has two writers). Actor.Do runs
	// on the actor goroutine; the deadline satisfies IF-02.
	broker := netctl.BrokerFunc{
		AuthorizeFn: func(ctx context.Context, mac string, ttl time.Duration) error {
			res := actor.Do(ctx, core.AuthorizeGuest{MAC: mac, TTL: ttl})
			return res.Err
		},
		RevokeFn: func(ctx context.Context, mac string) error {
			res := actor.Do(ctx, core.RevokeGuest{MAC: mac})
			return res.Err
		},
	}

	var nc netctl.NetCtl
	var realNC *netctl.Real // non-nil in production mode — the Deauth seam target
	var neighborProvider neighbors.Provider
	// The rtnetlink client feeds the neighbor watcher in BOTH modes:
	// neighbor reads are unprivileged kernel reads (the same data `ip
	// neigh show` would return), so -dev stays true to "no kernel
	// writes" while exercising the real watcher. Devices where the
	// netlink socket is unavailable fall back to the iproute2/mock path.
	nlClient := netlink.New()
	if *devMode {
		mock := netctl.NewMock()
		nc = mock
		// Real neighbor table via netlink when possible; the Mock's
		// seedable emulation when not (dev machines without the socket).
		neighborProvider = neighbors.ProviderFunc(func() []neighbors.Entry {
			if rows, err := nlClient.Dump(); err == nil {
				out := make([]neighbors.Entry, 0, len(rows))
				for _, n := range rows {
					out = append(out, neighbors.Entry{Interface: n.Iface, IP: n.IP, MAC: n.MAC, Seen: n.Seen})
				}
				return out
			}
			return neighbors.Adapt(mock.ListLiveNeighbors(), func(n netctl.LiveNeighbor) neighbors.Entry {
				return neighbors.Entry{Interface: n.Interface, IP: n.IP, MAC: n.MAC, Seen: n.Seen}
			})
		})
		log.Warn("using the in-memory NetCtl mock — nothing here writes nft, hostapd, or dnsmasq (-dev; neighbor reads stay real via rtnetlink)")
	} else {
		// Real NetCtl (IF-01): neighbor reads via rtnetlink (RTM_GETNEIGH,
		// iproute2 fallback), nft bindings via nft get element, guest
		// writes via the state actor.
		realNC = netctl.NewReal(broker, "br-guest")
		realNC.FlushConn = true
		realNC.NetlinkDumper = nlClient.Dump
		nc = realNC
		neighborProvider = neighbors.ProviderFunc(func() []neighbors.Entry {
			return neighbors.Adapt(realNC.ListLiveNeighbors(), func(n netctl.LiveNeighbor) neighbors.Entry {
				return neighbors.Entry{Interface: n.Interface, IP: n.IP, MAC: n.MAC, Seen: n.Seen}
			})
		})
		log.Info("real NetCtl active — neighbor table via rtnetlink, nft bindings kernel-backed")
	}

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
				// Janitor half of the Bouncer Tick (§4.6): demote expired
				// approvals before rebuilding the Plan.
				if demoted, err := store.FlushExpiredDevices(db, time.Now()); err != nil {
					log.Warn("expiry flush failed", "err", err)
				} else if len(demoted) > 0 {
					log.Info("devices expired to waiting-adjacent state", "count", len(demoted))
				}
				if err := handler.Sync(ctx); err != nil {
					log.Warn("periodic re-apply failed (will retry)", "err", err)
				}
			}
		}
	})

	// nc (IF-01) is consumed by portal-edge from M3; wiring it now keeps
	// the supervisor task alive and the contract exercised end-to-end.
	_ = nc

	// Waiting listeners (ERR-01): the info page + DNS REFUSED stub.
	// Clients reach them only through the nat_pre DNAT, so binding to
	// the wildcard is correct — the nftables mark rules are the gate.
	deviceView := func(ip net.IP) waitinghttp.DeviceView {
		// state.db is the source of truth; reads from the listener are
		// fine (single-writer applies to writes only).
		var mac, hostname, state string
		_ = db.QueryRow(`SELECT COALESCE(d.mac,''), COALESCE(d.hostname,''), COALESCE(d.state,'waiting')
			FROM ip_leases l JOIN devices d ON d.mac = l.mac WHERE l.ip4 = ?`, ip.String()).
			Scan(&mac, &hostname, &state)
		return waitinghttp.DeviceView{
			MAC: mac, IP: ip.String(), Hostname: hostname,
			State: state, Approved: state == "approved",
		}
	}
	sup.Add("waiting-http", func(ctx context.Context) {
		s := waitinghttp.New("10.20.99.1:8081", deviceView, log)
		if err := s.Run(ctx); err != nil {
			log.Error("waiting-http died", "err", err)
		}
	})
	dnsStub := waitingdns.New("10.20.99.1:5354", "waiting.kcp.internal", "10.20.99.1", log)
	sup.Add("waiting-dns", func(ctx context.Context) {
		if err := dnsStub.Run(ctx); err != nil {
			log.Error("waiting-dns died", "err", err)
		}
	})
	// Portal-edge (M3, §5): the guest DNAT lands on 10.20.3.1:8080 —
	// consent form → actor AuthorizeGuest (consent row + authed_guests)
	// → next reconcile lifts the DNAT for that MAC. nc (IF-01) supplies
	// the IP→MAC identity; it is wired before this point in both modes.
	mktKey, mktErr := store.GetSetting(db, "marketing_key")
	if mktErr != nil {
		mktKey = "" // no key = marketing sync disabled (client_ref empty)
	}
	psvc := portal.New(mktKey)
	portalEdge := portaledge.New(portaledge.Config{
		Addr:        "10.20.3.1:8080",
		GuestBridge: "br-guest",
		TTL:         time.Duration(cfg.Portal.SessionTTLMinutes) * time.Minute,
	}, db, nc, actor, psvc, log)
	sup.Add("portal-edge", func(ctx context.Context) {
		if err := portalEdge.Run(ctx); err != nil {
			log.Error("portal-edge died", "err", err)
		}
	})

	// REST admin (M3, §7.2): 127.0.0.1 by default — reachability beyond
	// loopback is the mgmt plane's business (drop-in ExecStart override
	// or an SSH tunnel; never 0.0.0.0). Token lives in state.db settings
	// and is shown once with -api-token.
	apiSrv := &api.Server{DB: db, Actor: actor, Portal: psvc, Confirmer: confirmer, Log: log}
	if tok, created, terr := api.LoadToken(db); terr != nil {
		log.Warn("api token unavailable — admin API stays authenticated-closed", "err", terr)
	} else {
		apiSrv.SetToken(tok)
		if created || *printAPIToken {
			fmt.Printf("api-token: %s\n", tok)
		}
		sup.Add("api-admin", func(ctx context.Context) {
			httpSrv := &http.Server{
				Addr:              *apiAddr,
				Handler:           apiSrv.Handler(),
				ReadHeaderTimeout: 3 * time.Second,
			}
			errCh := make(chan error, 1)
			ln, lerr := net.Listen("tcp", *apiAddr)
			if lerr != nil {
				log.Error("api-admin listen failed", "err", lerr)
				return
			}
			go func() {
				if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
				close(errCh)
			}()
			log.Info("admin api listening", "addr", ln.Addr().String())
			select {
			case <-ctx.Done():
				shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = httpSrv.Shutdown(shutCtx)
				<-errCh
			case err := <-errCh:
				log.Error("admin api died", "err", err)
			}
		})
	}

	// Watchers (MOD-BOUNCER detection sources, DD-03): the lease hook
	// socket (IF-05b) and the live neighbor cache. Lease events feed the
	// actor through store mutations + handler.Sync, keeping PD-3 intact.
	onLease := func(ev dhcphook.Event) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		switch ev.Action {
		case "del":
			if err := store.RemoveLease(db, ev.MAC); err != nil {
				log.Warn("lease removal failed", "err", err)
			}
			return // cache-only: non-reserved lease rows are not rendered
		case "add", "old":
			if _, err := store.UpsertSeenDevice(db, ev.MAC, ev.Hostname, ev.Interface, time.Now()); err != nil {
				log.Warn("device bookkeeping failed", "err", err)
			}
			if err := store.UpsertLease(db, ev.MAC, ev.IP, 2*time.Hour, time.Now()); err != nil {
				log.Warn("lease bookkeeping failed", "err", err)
			}
		default:
			log.Warn("unknown lease action", "action", ev.Action)
			return
		}
		if err := handler.Sync(ctx); err != nil {
			log.Warn("reconcile after lease event failed", "err", err)
		}
	}
	hookWatcher := dhcphook.New(*nftDir, onLease, log)
	sup.Add("dhcp-hook", func(ctx context.Context) {
		if err := hookWatcher.Run(ctx); err != nil {
			log.Error("dhcp hook watcher died", "err", err)
		}
	})
	// Production runtime config (M2 wiring, real mode only): bridges are
	// the operator's one-time job (deploy/pi/kcp-net-apply.sh — the step
	// able to cut management access stays manual). Once they exist, this
	// task renders hostapd.conf + dnsmasq.conf + hosts.d from state.db
	// deterministically, rewrites only on drift, and reloads what it can.
	if !*devMode {
		if err := runtimecfg.RequireBridges(log); err != nil {
			log.Warn("runtime config disabled — Wi-Fi/DHCP rendering skipped", "err", err)
		} else {
			sup.Add("ap-config-render", func(ctx context.Context) {
				apply := func(reason string) {
					// hostapd.conf: PSK dari staff_psk (produksi) atau env
					// KCP_STAFF_PSK (lab bootstrap). Kosong keduanya = render
					// dilewati, bukan config AP yang rusak.
					psk, perr := store.GetSetting(db, "staff_psk")
					if perr != nil || psk == "" {
						psk = os.Getenv("KCP_STAFF_PSK")
					}
					// KCP_WIFI_BSS=single: documented fallback for radios
					// whose firmware cannot run two concurrent APs (the Pi 5's
					// CYW43455 reports #{ AP } <= 1 — DD-01 dual BSS fails with
					// EBUSY). The surviving BSS is the guest portal one.
					var hout []byte
					var herr error
					if os.Getenv("KCP_WIFI_BSS") == "single" {
						hout, herr = runtimecfg.RenderHostapdSingleBSS(ssidOf(cfg.SSIDs, 1))
					} else {
						if psk == "" {
							log.Warn("hostapd render skipped — no staff_psk setting / KCP_STAFF_PSK env yet")
							goto dnsmasqRender
						}
						hout, herr = runtimecfg.RenderHostapd(ssidOf(cfg.SSIDs, 0), ssidOf(cfg.SSIDs, 1), psk)
					}
					// The ctrl_interface dir must pre-exist and be group-writable:
					// the hostapd unit runs root:kcportal WITHOUT DAC_OVERRIDE,
					// and /run/kcportal itself is 0755 kcportal-only.
					if mkerr := os.MkdirAll(filepath.Join(*nftDir, "hostapd"), 0o770); mkerr != nil {
						log.Warn("ctrl_interface dir create failed", "err", mkerr)
					}
					if herr != nil {
						log.Warn("hostapd render failed", "err", err)
						// 0640 group kcportal: the hostapd unit runs with
						// Group=kcportal and a capability bounding set WITHOUT
						// DAC_OVERRIDE, so root-only 0600 would be unreadable there.
					} else if changed, err := writeFileIfChanged(filepath.Join(*nftDir, "hostapd.conf"), hout, 0o640); err != nil {
						log.Warn("hostapd.conf write failed", "err", err)
					} else if changed {
						log.Info("hostapd.conf updated — restarting hostapd@kcportald", "reason", reason)
						runtimecfg.RestartHostapd(log)
					}
				dnsmasqRender:
					// dnsmasq.conf + hosts.d (§4.5): reservations flow through
					// the inotify dir (no restart needed); pool-level conf
					// changes restart dnsmasq-kcp below (polkit-pinned).
					out, resv, err := runtimecfg.RenderDnsmasq(db, []string{"1.1.1.1", "9.9.9.9"}, map[int]string{1: "z1", 2: "z2"}, "12h")
					if err != nil {
						log.Warn("dnsmasq render failed", "err", err)
						return
					}
					dnsDir := filepath.Join(*nftDir, "dnsmasq")
					confChanged, err := writeFileIfChanged(filepath.Join(dnsDir, "dnsmasq.conf"), out, 0o640)
					if err != nil {
						log.Warn("dnsmasq.conf write failed", "err", err)
						return
					}
					resvChanged, err := dhcp.WriteReservations(filepath.Join(dnsDir, "hosts.d"), resv)
					if err != nil {
						log.Warn("hosts.d sync failed", "err", err)
						return
					}
					if confChanged {
						log.Info("dnsmasq.conf updated — restarting dnsmasq to apply pool changes", "reason", reason)
						runtimecfg.RestartDnsmasq(log)
					} else if resvChanged > 0 {
						// Per-file hosts.d changes ride dnsmasq's inotify — the
						// restart would be redundant; a log line is the audit trail.
						log.Info("hosts.d reservations updated (dnsmasq inotify applies them)", "files", resvChanged, "reason", reason)
					}
				}
				apply("startup")
				t := time.NewTicker(30 * time.Second) // same cadence as drift-reapply
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						apply("periodic")
					}
				}
			})
		}
	}

	// Wi-Fi control plane (IF-05a, MOD-WIFI): in production the hostapd
	// ctrl sockets carry both the Bouncer's event stream (AP-STA-*,
	// consumed and logged here; enrichment lands with the M3 Bouncer
	// scoring) and the DEAUTH path netctl.Real uses to kick a guest off
	// the radio AFTER the nft revoke took effect (§4.6 effect ordering —
	// nft first, radio second). The client keeps PING keepalives +
	// re-attach alive across hostapd restarts; sockets are per-BSS
	// (wlan0, wlan0_1 — or only wlan0 in KCP_WIFI_BSS=single).
	var hapd *hostapdctl.Client
	if !*devMode {
		bssList := []string{radioIface()}
		if os.Getenv("KCP_WIFI_BSS") != "single" {
			bssList = append(bssList, radioIface()+"_1")
		}
		hapd = hostapdctl.NewClient("/run/kcportal/hostapd", bssList, log)
		sup.Add("hostapd-ctl", func(ctx context.Context) {
			if err := hapd.Run(ctx); err != nil {
				log.Error("hostapd-ctl died", "err", err)
			}
		})
		sup.Add("hostapd-events", func(ctx context.Context) {
			events := hapd.Events()
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-events:
					switch ev.Kind {
					case hostapdctl.StaConnected:
						log.Info("sta connected", "bss", ev.BSS, "mac", ev.MAC)
					case hostapdctl.StaDisconnected:
						log.Info("sta disconnected", "bss", ev.BSS, "mac", ev.MAC)
					}
				}
			}
		})
		// The radio kick rides the netctl.DeauthFunc seam: Real calls it
		// best-effort on every RevokeGuest, after the kernel side is done.
		realNC.Deauth = func(mac string) error {
			var firstErr error
			for _, bss := range bssList {
				if err := hapd.Deauthenticate(bss, mac); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			return firstErr
		}
		log.Info("hostapd control wired — DEAUTH on revoke active", "bss", bssList)
	}

	neighborCache := neighbors.NewCache(neighborProvider, 5*time.Minute)
	sup.Add("neighbor-watcher", func(ctx context.Context) { // Push half: RTM_NEWNEIGH updates merge near-instantly; the same
		// task also runs the poll half as the resynchronization path.
		// (Bind to RTNLGRP_NEIGH needs CAP_NET_ADMIN — the systemd unit
		// grants it; sandbox/dev boxes degrade to poll-only.)
		{
			nl := netlink.New()
			updates, stopSub, err := nl.Subscribe(ctx)
			if err != nil {
				log.Warn("netlink subscribe unavailable — poll-only neighbor watching", "err", err)
			} else {
				defer stopSub()
				go func() {
					for ne := range updates {
						neighborCache.Merge(neighbors.Entry{Interface: ne.Iface, IP: ne.IP, MAC: ne.MAC, Seen: ne.Seen})
						neighRev.Add(1)
					}
				}()
			}
		}
		neighborCache.Run(ctx, 5*time.Second) // poll half: resync cadence 5s (≤2s detection budget vs Pi cost)
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

// ssidOf pulls the configured SSID for a BSS slot (0=staff, 1=guest);
// empty when config did not define it (renderer falls back to defaults).
func ssidOf(ssids []config.SSID, i int) string {
	if i < len(ssids) {
		return ssids[i].SSID
	}
	return ""
}

// radioIface finds the Wi-Fi radio for the hostapd ctrl client (the
// same wlan0* detection the config renderer uses; empty fallback keeps
// the client's socket path construction total).
func radioIface() string {
	if name, ok := runtimecfg.DetectIFace("wlan0"); ok {
		return name
	}
	return "wlan0"
}

// writeFileIfChanged writes data atomically (tmp→rename) only when the
// current content differs — the same no-churn rule the nft renderer
// follows, so inotify-driven consumers and restarts stay quiet.
func writeFileIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	cur, err := os.ReadFile(path)
	if err == nil && bytes.Equal(cur, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	return true, nil
}
