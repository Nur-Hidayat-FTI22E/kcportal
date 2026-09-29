# kotacloud-portal

Captive-portal Wi-Fi router + Point-of-Sale App Pack for a single-box
venue (café pilot), implemented in Go for Raspberry Pi 5. One daemon
(`kcportald`) owns the router: nftables enforcement, DHCP/DNS, Wi-Fi
access points, the guest portal, a REST admin API with an embedded web
GUI, and a rootless-containerized PoS behind TLS.

> Status: **M0–M4 complete and verified live on a Pi 5** — router with
> captive portal, admin GUI, DoH shield, PoS App Pack. M5 (fleet
> server) is next; see the [roadmap](docs/ROADMAP.md) and the
> [milestone status](#milestone-status) below.

---

## Features

**Guest internet, the safe way**

- Consent-first captive portal (`terms` required, marketing optional,
  voucher support) — identity resolved **only** from the kernel
  neighbor table (IP → MAC), never from client-supplied data.
- OS captive-probe handling: `/generate_204` and friends get a 302 so
  Android/iOS/Windows pop their own portal window.
- **DoH/DoT shield**: public-resolver bootstrap IPs (Cloudflare,
  Google, Quad9, OpenDNS, AdGuard) and ports 853 are dropped for guest
  traffic, so Android Private DNS falls back to the venue DNS and the
  portal flow always wins. Live counters exposed to the admin GUI.
- Time-boxed guest sessions (`authed_guests` nftables set with
  timeouts), revocation with radio deauthentication (§4.6 ordering:
  kernel first, radio second).

**Single-box router**

- Declarative ruleset: desired state in SQLite (`state.db`) → rendered
  `kcp.nft` → validated with `nft -c` → installed atomically with
  `nft -f` (never `flush ruleset`). 30 s drift re-apply loop.
- Commit-confirm for risky changes (ADR-006): a 60 s trial with
  automatic rollback to the last-good snapshot unless confirmed —
  from the API, the GUI, or the boot path after a crash.
- Zones (waiting/admin/pos/guest), MAC classification, anti-spoof
  MAC-IP bindings (SEC-012), per-client guest bandwidth limits,
  SMTP block, conntrack caps.

**Admin**

- REST API (`/api/v1/*`, bearer token, loopback-only listener) +
  embedded React GUI: device approval, live guest sessions with
  revoke, voucher generation, zone policy (rides commit-confirm),
  hash-chained audit log, WAN setup wizard, DoH shield monitoring.
- Wi-Fi config rendered from state (hostapd + dnsmasq), restarts via
  polkit-pinned systemctl; per-device DHCP reservations ride dnsmasq's
  inotify (no restarts).

**PoS App Pack (M4)**

- `pos-cafe` runs rootless in Podman (Quadlet), uid `kcapps`, with a
  **default-deny egress** chain (`meta skuid`) — only explicitly
  allowed destinations pass.
- Cashier web UI (embedded React): PIN login (argon2id), shifts with
  the single-open rule enforced by the database, orders with per-day
  receipt numbering (`YYMMDD-0001`), cash + manual-QRIS payments with
  idempotency keys, admin-only void with audited reasons.
- Receipts: ESC/POS 58 mm renderer with USB and raw-TCP drivers; the
  print job is committed **in the same transaction** as the payment
  (FR-POS-007) and a worker drains the queue with backoff.
- `pos.db` is fully decoupled from `state.db` (§6.5):
  `synchronous=FULL`, single write connection — 0 lost transactions on
  power cut (NFR-POS-03).
- TLS everywhere the cashier touches: venue-local CA (T1) served by
  `pos-onboard`, terminated by `pos-proxy` (:8443), app on loopback
  only.

## Architecture

```
                       internet
                          │
┌─────────────────────────┼────────────────────────── Pi 5 ─────────┐
│                      eth0 (uplink)                                │
│                                                                   │
│  kcportald (system daemon)                                        │
│   ├─ state.db (SQLite)  ← single state actor (PD-3)               │
│   ├─ nftables: kcp_zones/kcp_filter/kcp_portal/kcp_nat            │
│   ├─ hostapd@kcportald (Wi-Fi APs)   dnsmasq-kcp (DHCP/DNS)       │
│   ├─ portal-edge :8080 (guest portal, embedded React)             │
│   └─ admin API :8083 (REST + embedded React GUI)                  │
│                                                                   │
│  PoS plane (br-lan / POS zone)                                    │
│   ├─ pos-onboard :8082  (local CA + ca.crt download)              │
│   ├─ pos-proxy :8443    (TLS, venue CA) → 127.0.0.1:8444          │
│   └─ pos-cafe (rootless Podman, uid kcapps)                       │
│        └─ pos.db (/var/lib/kcportal/pos, FULL sync)               │
└───────────────────────────────────────────────────────────────────┘
        │ br-lan (staff/POS)         │ br-guest (captive guests)
     cashiers, admin              phones → portal
```

Key invariants: **one state writer** (commands via a single actor),
**generated config, never hand-edited**, **fail-closed everywhere**
(nft `-c` before `-f`, bridges must exist, egress default-deny), and
**secrets never in app.yaml or state.db** (§7.3).

## Quick start (lab)

On a Raspberry Pi 5 (Debian 13) with the repo cloned:

```sh
# 1. Router interfaces (bridges, addresses, forwarding) — manual and
#    reviewed by design, this step can cut management access.
sudo deploy/pi/kcp-net-apply.sh --keep-eth0

# 2. Run the daemon (dev dry-run: no kernel writes, in-memory NetCtl)
sudo systemctl enable --now kcportald          # production posture
#   or: go run ./cmd/kcportald -dev            # laptop dry-run

# 3. Admin API token (shown once)
sudo kcportald -api-token
ssh -L 8083:127.0.0.1:8083 pi@<pi>             # then open http://127.0.0.1:8083
```

Guests join the portal SSID, open any HTTP site, get the consent page,
and are online after accepting. Devices can also be approved per-MAC
from the admin GUI (zones: admin/pos/guest).

### PoS App Pack

```sh
sudo deploy/pi/pos/pos-setup.sh                # podman, kcapps user, units
deploy/pi/pos/build-pos-image.sh               # build the image ON the Pi
# install pos-proxy/pos-onboard binaries + units (see deploy/pi/pos/README.md)
sudo deploy/pi/pos/verify-pos.sh               # acceptance: 14 checks + power-cut drill
```

Full operational details (printer wiring for USB and LAN modes,
cashier browser onboarding, binary update flow) are in
[`deploy/pi/pos/README.md`](deploy/pi/pos/README.md).

## Repository layout

```
cmd/kcportald          single daemon: wiring of everything below
cmd/pos-cafe           PoS application (App Pack, rootless container)
cmd/pos-proxy          TLS terminator :8443 → pos-cafe
cmd/pos-onboard        venue-local CA + ca.crt download :8082
internal/api           REST admin API + embedded web GUI mount
internal/config        app.yaml shape + validation
internal/confirm       commit-confirm manager (ADR-006)
internal/core          command/result/actor/event bus (IF-02, PD-3)
internal/listen/       portal-edge (guest portal), waiting-* listeners
internal/net/          netctl (IF-01), nft renderer, dhcp, wifi, netlink
internal/pos/          pos.db store, local PKI, ESC/POS printer, cashier UI
internal/portal        guest session domain (DD-11 pseudonym, view model)
internal/reconcile     state actor handler: state.db → Plan → nft
internal/runtimecfg    hostapd/dnsmasq renderers + restart plumbing
internal/store         state.db (SQLite) + migrations
internal/supervisor    task lifecycle runner
internal/watchers      dhcp-hook, neighbor (netlink) watcher
web/admin              React GUI (embedded via internal/api/webadmin)
web/portal             React captive page (embedded via portaledge/web)
web/pos                React cashier UI (embedded via internal/pos/web)
deploy/pi/             deployment scripts, units, docs for the Pi
docs/ROADMAP.md        milestone breakdown + status
docs/M4-plan.md        PoS App Pack plan with live evidence
```

## Milestone status

| Milestone | Scope | Status |
|---|---|---|
| M0 | Skeleton, state.db schema, actor/bus, CI | ✅ done |
| M1 | state.db → Plan → nft pipeline, commit-confirm | ✅ done |
| M2 | Wi-Fi APs, DHCP/DNS, DEAUTH enforcement, Pi live | ✅ done |
| M3 | Guest portal, REST admin, web GUIs, DoH shield | ✅ done |
| M4 | PoS App Pack (Podman, TLS, PoS app, egress deny) | ✅ done |
| M5 | Fleet server (enroll, poll/ack, marketing sync) | planned |
| M6 | Public TLS (ACME), DoT upstream, hardening | planned |

Verification: `go test -race ./...` (all green), golden-file ruleset
tests, live acceptance on the Pi (`deploy/pi/pos/verify-pos.sh`,
14 checks) and per-milestone evidence in `docs/M4-plan.md`.

## Device notes (Pi 5 / CYW43455)

- The onboard radio reports `#{ AP } <= 1`: only one BSS is possible
  (the guest portal one). DD-01's dual BSS returns with a second radio.
- The guest SSID runs **2.4 GHz** (`hw_mode g`, channel 6, HT20) — the
  5 GHz band kept some phones from ever associating.
- hostapd 2.10 on this firmware emits no `AP-STA-*` ctrl events at all
  (verified with two independent listeners). Enforcement is
  unaffected: the reconciler owns state, DEAUTH is best-effort radio
  hygiene.

## Docs

- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones, open gaps
- [`docs/M4-plan.md`](docs/M4-plan.md) — PoS plan + live evidence
- [`deploy/pi/README-production.md`](deploy/pi/README-production.md) — production deployment
- [`deploy/pi/RECOVERY.md`](deploy/pi/RECOVERY.md) — lockout recovery
- [`deploy/pi/pos/README.md`](deploy/pi/pos/README.md) — PoS operations

## License

All rights reserved. Internal project — licensing decided before any
distribution.
