# Roadmap kerja (usulan)

`kotacloud-portal-software-design.md` menyebut milestone M0-M4 didefinisikan
di §12 dari spec dasar (`kotacloud-wifi.md` v0.4) — file itu tidak ikut
ter-upload, jadi breakdown di bawah ini **usulan saya**, disusun mengikuti
batas modul yang memang tertulis di SDD-Design (`MOD-`/`IF-`/`DD-`).
Sesuaikan urutannya kapan saja — ini bukan kutipan dari §12 aslinya.

## M0 — Fondasi (selesai di iterasi ini)

- Skeleton repo Go: `internal/core` (Command/Result/Actor/Bus — IF-02,
  PD-3), `internal/net/netctl` (kontrak IF-01 + `Mock` in-memory untuk dev
  tanpa Pi), `internal/config` (app.yaml + default Café MVP),
  `internal/store` (state.db SQLite + migrasi, WAL/`synchronous=NORMAL`
  sesuai §8), `internal/supervisor` (lifecycle task runner, cikal bakal
  watchdog Appendix F.2).
- `cmd/kcportald -dev` sudah bisa dijalankan end-to-end (tanpa nft/root).
- **[Selesai]** Skema dasar `state.db` (`internal/store/migrations/0001_base.sql`)
  sekarang skema ASLI dari `kotacloud-wifi-skema.sql` (Appendix D+H
  spec v0.4, digabung dengan delta desain §8) — bukan stub lagi. Sudah
  diuji nyata lewat `sqlite3` (Python stdlib, offline): semua `CREATE
  TABLE` berhasil, dan constraint `CHECK devices.state` serta partial
  unique index "satu shift terbuka" (di skema pos.db) terbukti menolak
  data yang melanggar.
- Skema `pos.db` (App Pack, M4) dan `kcp_server` MySQL/MariaDB (M5) ikut
  disimpan sebagai referensi — belum dipakai kode apa pun, menunggu
  milestone masing-masing:
  - `web/pos/migrations/0001_pos_db.sql`
  - `server/migrations/0001_kcp_server_mysql.sql`

**Gap yang masih perlu kamu isi sebelum M1 serius:**

1. Printer struk pilot pertama: USB atau LAN? Menentukan
   `AddDevice=/dev/usb/lp0` vs `POS_PRINTER=tcp:10.20.2.20:9100` (§7.1 IF-03).
2. T1 vs T2 untuk TLS di pilot pertama (CA lokal vs ACME publik, DD-09) —
   dokumen sendiri bilang publik "sebelum go-live", jadi T1 masuk akal
   untuk kafe pilot.
3. Prefix IPv6 IndiHome di lokasi pilot (PD vs RA-only) — menentukan
   DD-08/SCR-04 (native /64 per segmen vs NAT66 ULA).

## M1 — Reconciler & klasifikasi zona (§4.2-4.3)

- `internal/net/nft`: bangkitkan & apply tabel `kcp_zones`/`kcp_filter`/
  `kcp_portal`/`kcp_nat`/`kcp_l2` (§4.3) lewat `nft -f` atomik + `nft -c`
  (DD-04) — **bukan** `flush ruleset`.
- Handler nyata di `Actor` (state.db -> Plan -> transaksi nft),
  commit-confirm untuk perubahan yang bisa mengunci admin keluar
  (`Result.Deadline`, IF-02).
- Bouncer: klasifikasi MAC->zona, watcher hook lease dnsmasq + neighbor
  netlink (DD-02, DD-03, DD-10).

## M2 — Wi-Fi, DHCP/DNS, Waiting (§2.3, §4.1, DD-06)

- Generator `hostapd.conf` (2 BSS -> 2 bridge, DD-01) dan `dnsmasq.conf` +
  hostsdir, ditulis ke tmpfs `/run/kcportal/*` (PD-4).
- Listener `waiting-http`/`waiting-dns` + stub DNS `REFUSED` (ERR-01/DD-06).
- `NetCtl` asli (netlink + `nft`) menggantikan `netctl.Mock`.

## M3 — Portal tamu + REST admin (§5, §7.1 IF-01, §7.2)

**Status: inti jalan (2026-09-29).**

- [x] `portal-edge` (internal/listen/portaledge): identifikasi tamu
  dari neighbor table (DD-10), consent + voucher → `AuthorizeGuest`
  (metadata consent + konsumsi voucher dalam satu langkah actor),
  sesi (`guest_sessions`, §8), `/state` polling.
- [x] `internal/api`: `/api/v1/devices|guests|zones|changes|audit|vouchers`
  dengan bearer token (settings, tampil via `-api-token`).
- [x] Endpoint setup wizard + `/network/wan` (2026-09-29): GET posture
  view (deteksi iface/uplink/bridge) + POST record intent (settings
  `wan_config` + audit + app.yaml); kernel reconfig tetap manual via
  `kcp-net-apply.sh` (DD-15).
- [ ] `web/portal` + `web/admin` (React, statis, di-embed) — halaman
  Go saat ini fungsional tapi minimal.
- [ ] Sync pemasaran ke kcp-server (client_ref) — M5 `portal.sync`,
  pseudonym sudah dicetak di sini.

## M4 — PoS App Pack (§7.1 IF-03, §6.5)

- Podman/Quadlet rootless `pos-cafe`; proxy `apps` (:8443) + `pos-onboard`
  (:8082, CA lokal T1); egress dibatasi `meta skuid` (DD-14).
- Printer USB atau LAN (lihat gap #2 di atas).
- PoS sendiri: SQLite `synchronous=FULL`, satu koneksi tulis (DD-12/ERR-06).

## M5 — Server fleet (§6, MOD-SERVER)

- `server/`: Go `net/http` + MySQL + Redis; enroll (§6.13, SCR-07),
  poll/ack idempoten (§6.3, IF-04), rollout artifact, sinkron pemasaran
  via `client_ref` HMAC (DD-11/SCR-08), backup.
- Skema §6.4 (`artifacts`/`rollouts`/`guest_leads`/`backups`/
  `unit_events`/`audit_server`).

## M6 — TLS publik, DoT, hardening (DD-09 T2, DD-16, §11.2 TV-xx)

- ACME DNS-01 per-unit setelah T1 terbukti stabil di pilot.
- `unbound` DoT bila headroom RAM terbukti (DD-16).
- Beresi semua **TV-xx** (titik verifikasi teknis) yang mensyaratkan
  pengujian di perangkat/netns nyata — lihat §11.2 dokumen SDD-Design.
