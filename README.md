# kotacloud-portal

Implementasi bertahap dari `kotacloud-portal-software-design.md`
(SDD-Design v0.1). Lihat `docs/ROADMAP.md` untuk pembagian milestone dan
gap yang perlu keputusanmu sebelum lanjut ke M1.

## Status: M0–M4 tuntas di Pi — router captive (M0–M2), portal + admin + web GUI + DoH shield (M3), PoS App Pack rootless (M4): pos-cafe live di balik TLS :8443 dengan egress default-deny & verifikasi 14/14

**Baru (M3.5): DoH/DoT shield** — Android Private DNS / Chrome DoH
bisa melewati captive flow sepenuhnya (tamu tidak pernah kena DNAT :80,
HP menyatakan "tidak ada internet" alih-alih membuka portal — teramati
langsung dengan HP tamu). Mitigasi di `kcp_portal.gate_fwd`
(`nft.DoHShield`, default aktif): IP bootstrap resolver publik
(1.1.1.1, 8.8.8.8, 9.9.9.9, dst.) diblok untuk seluruh trafik br-guest
+ DoT/DoQ :853 di-drop — Private DNS gagal bootstrap, OS fallback ke
DNS DHCP (dnsmasq), dan captive flow berjalan normal. Berlaku juga
untuk sesi yang sudah authorized (kebijakan DNS venue bagian dari
sesi); query upstream router sendiri tidak terdampak.

**Baru (M3): web/admin GUI** — React + Vite + TypeScript di-embed ke
binary (`internal/api/webadmin`) dan dilayani dari listener REST yang
sama (`127.0.0.1:8083`): shell statis tanpa token (halaman login harus
bisa dimuat dulu), semua `/api/*` tetap bearer-token. Tab: setup
wizard WAN, devices (approve/block), sesi tamu (revoke), voucher
(generate/list), zona + policy dengan banner commit-confirm
(`/changes/pending` kini membawa `change_id` + `risk_reason`), audit
log. `dist/` di-commit sehingga CI tetap Go-only; dev mode pakai
`npm run dev` + SSH tunnel (lihat `web/admin/README.md`).

**Baru (M3 inti): portal tamu + REST admin** — tiga paket:

- `internal/portal` — domain sesi tamu: pseudonym pemasaran DD-11
  (`client_ref = hex(HMAC-SHA256(key, mac))` — MAC tak pernah keluar
  unit), encoder payload consent deterministik, dan read model
  `View()` yang menggabungkan devices + guest_sessions.
- `internal/listen/portaledge` — captive portal di 10.20.3.1:8080:
  identitas klien **hanya** dari IP sumber → neighbor table (DD-10) +
  cross-check binding SEC-012; halaman consent kini SPA React
  (`web/portal`, di-embed via `internal/listen/portaledge/web` — pola
  sama dengan web/admin, kontrak kawat tak berubah: `POST /` form,
  `/state` polling, catch-all 302 probe; error inline di halaman),
  voucher opsional yang dikonsumsi **di dalam** langkah penulis
  tunggal — kode habis/invalid gagal tanpa membuka sesi.
- `internal/api` — REST admin §7.2 (subset yang sudah dilayani
  state.db): devices (list/approve/block), guests (list/revoke),
  zones + policy (PUT zona Admin otomatis masuk commit-confirm dan
  endpoint `/changes/pending` + `/changes/confirm` menampilkan/
  menerima trialnya — IF-02), audit (hash chain, read-only), voucher
  (generate/list), dan setup wizard `/network/wan` (GET posture:
  deteksi iface/uplink/bridge; POST {wan:{mode}, iface}: catat niat
  ke settings `wan_config` + audit + app.yaml — **tanpa** sentuh
  kernel; bridging uplink tetap milik `kcp-net-apply.sh`, DD-15).
  Auth bearer token yang di-generate sekali di
  settings dan ditampilkan via `kcportald -api-token`; listener
  default `127.0.0.1:8083` (buka lewat SSH tunnel / mgmt plane).

**Baru (M1): `internal/net/nft`** — generator ruleset `kcp_zones`/
`kcp_filter`/`kcp_portal`/`kcp_nat`/`kcp_l2` (§4.3) dari desired state
(`Plan`), divalidasi `nft -c -f` lalu dipasang atomik `nft -f`
(DD-04, **tanpa** `flush ruleset`), fail-closed (NFR-REL-04): kalau
`nft -c` menolak, ruleset lama tetap jalan. Output golden-file
diverifikasi parser `nft` asli.

**Baru (M1): pipeline state.db → Plan → nft** — `internal/reconcile`
adalah Handler nyata state actor: setiap Command (ApproveDevice /
AuthorizeGuest / RevokeGuest) menulis ke state.db dulu (PD-3: satu
penulis), lalu Plan dibangun ulang dari `store.LoadPlan` dan ruleset
baru di-render + di-apply. Startup melakukan `Sync` awal, dan goroutine
`drift-reapply` mengulang setiap 30 detik (catatan §4.3). Zona di-seed
dari config saat boot (`store.EnsureSeedZones`, zona Waiting virtual —
`devices.state`, bukan baris, sesuai CHECK skema asli). Flag baru:
`-nft-dir` (tmpfs PD-4), `-setup` (DD-15), `-dev` sekarang benar-benar
tanpa sentuhan kernel (nft -c pun butuh CAP_NET_ADMIN untuk cache
netlink-nya).

**Bisa dikompilasi & di-vet tanpa dependency eksternal apa pun**
(`go build ./internal/core/... ./internal/net/netctl/... ./internal/supervisor/...`):

- `internal/core` — `Command`/`Result`/`Actor`/`Bus` (kontrak IF-02,
  prinsip PD-3 "satu penulis").
- `internal/net/netctl` — kontrak `NetCtl` (IF-01) + `Mock` in-memory
  untuk dev/test tanpa root dan tanpa Pi.
- `internal/supervisor` — lifecycle task runner.

**Sudah ditulis, tapi butuh dua dependency eksternal**
(`modernc.org/sqlite`, `gopkg.in/yaml.v3`) yang tidak bisa saya unduh dari
sandbox tempat saya menulis ini — sandbox itu tidak punya akses ke proxy
modul Go. Jalankan `go mod tidy` di mesinmu sendiri (yang punya internet
normal) sebelum build:

- `internal/config` — baca `app.yaml`, jatuh ke default Café MVP kalau
  belum ada file (DD-15 setup mode).
- `internal/store` — buka `state.db` (SQLite), migrasi otomatis, pragma
  `journal_mode=WAL` + `synchronous=NORMAL` sesuai §8 (**beda** dari
  `pos.db` PoS yang `FULL`, DD-12 — jangan pakai ulang paket ini untuk
  `pos.db`). Skema di `migrations/0001_base.sql` sekarang skema ASLI
  (Appendix D+H spec v0.4 + delta desain §8), sudah diuji lolos `sqlite3`
  sungguhan — bukan stub lagi.
- `cmd/kcportald` — wiring semuanya jadi satu proses yang bisa jalan.

Sumber data nyata state.db→Plan dan pemasangan dari state actor kini
aktif.

**Baru (M1): Bouncer watcher (DD-02/03/10, IF-05b)** —
`internal/watchers/dhcphook` mendengarkan unix socket `hook.sock`
(IF-05b): lease dnsmasq (`add|old|del`) masuk sebagai JSON satu baris,
MAC dinormalisasi lowercase, event tak dikenal dibuang. Setiap event
membukuskan perangkat (state Waiting implisit di nft) + lease di
state.db lalu memicu Sync; reservasi IPAM (approved) tidak bisa
digeser/dihapus oleh hook. `internal/watchers/neighbors` menjaga cache
neighbor live (in-memory, refresh 5 s, TTL 5 menit) dari Provider —
netlink asli menyusul di M2, Mock sudah menyediakan dump-nya. Janitor
di drift-reapply memicu `FlushExpiredDevices` (approval lewat →
expired). Flood cap FR-BNC-007: tabel devices dibatasi 256 baris
terlama dibuang, approved dilindungi, event `bouncer.flood` ke caller.
Sisa M1: commit-confirm (IF-02).

**Baru (M1): NetCtl asli (IF-01)** — `netctl.Real`: pembacaan kernel
langsung (`ip neigh` dengan cache TTL 5 s + fallback dump penuh;
`nft get element` untuk SEC-012 Bound dengan saksi neighbor sebagai
fallback; hitung `authed_guests` dari `nft list set`), sedangkan
authorize/revoke tamu di-broker lewat state actor (`BrokerFunc` →
`Actor.Do`) sesuai §7.3 — authed_guests tak pernah punya dua penulis.
Revoke best-effort `conntrack -D`; DEAUTH hostapd menyusul di M2.
Diuji dengan fake runner ip/nft + fake broker (10 test `-race`).
Mode `-dev` tetap Mock; mode production kini memakai Real (butuh
CAP_NET_ADMIN — di sandbox tanpa privilege, `nft -c` menolak dan
fail-closed bekerja seperti desain).

**Baru (M1): commit-confirm (§4.7, ADR-006, IF-02)** —
`internal/confirm`: perubahan berisiko (kebijakan zona Admin yang bisa
memutus reachability listener mgmt; WAN/SSID menyusul) di-apply
provisional lalu `pending.json` (atomik, tmp+rename) + snapshot
`last-good.nft` ditulis dan timer 60 s berjalan. Confirm (M3 GUI →
`Confirm(changeID)`) menghapus marker; timeout/crash → rollback ke
snapshot. Boot yang menemukan `pending.json` yatim langsung rollback
sebelum serve. `Result.Deadline` terisi hanya untuk perubahan berisiko
(IF-02). `PutZonePolicy` kini menulis kolom kebijakan tabel `zones`
(internet, vpn_policy, lan_allow JSON) — DB, bukan config, yang
menjadi sumber policy saat render. Dengan ini cakupan M1 yang bisa
dikerjakan tanpa perangkat nyata sudah tuntas.

**Baru (M2 mulai): generator Wi-Fi & DHCP/DNS** — `internal/net/wifi`
me-render `hostapd.conf` (§4.4): dua BSS dengan pasangan bridge tetap
DD-01 (Staff→br-lan WPA2, Guest→br-guest open FR-WIF-010), satu band
untuk semua BSS (LIM-05), VHT seg0 = kanal+6, `ap_isolate=1` per BSS;
PSK disuntik dari secrets saat render — config tanpa PSK menolak
render, dan PSK tidak pernah masuk state yang persisten.
`internal/net/dhcp` me-render `dnsmasq.conf` (§4.5): Waiting satu-satunya
pool dinamis di br-lan (120 s, FR-NET-003), pool zona approved static
(TV-02 — perangkat tak dikenal hanya bisa dapat alamat Waiting), guest
dinamis 2 jam, `rebind-localhost-ok` (SEC-011), address captive
`kcp.internal`, option 114 tetap komentar sampai T2 (DD-09/ERR-07);
ditambah `WriteReservations` — sinkronisasi `hosts.d/` satu berkas per
MAC (tmp→rename atomik, file basi dihapus, file tak berubah tidak
di-tulis ulang agar inotify dnsmasq tidak churn). Output kedua generator
deterministik (syarat hash-check reconciler); 19 test `-race` hijau.
**Baru (M2): listener Waiting (ERR-01)** — `internal/listen/waitinghttp`
(halaman info + `/state` JSON untuk polling 3 detik, identitas klien
dari sumber-IP via state.db sesuai DD-10) dan
`internal/listen/waitingdns` (stub DNS :5354, format wire stdlib murni:
`REFUSED` untuk semua nama kecuali `waiting.kcp.internal` A →
10.20.99.1, UDP+TCP port sama, counter REFUSED untuk /metrics).
Keduanya bind dengan `IP_FREEBIND` sesuai §2.4 — alamat 10.20.99.1
boleh belum ada saat boot (bridge dibuat reconcile belakangan).
4 test `-race` (query DNS wire sungguhan via UDP/TCP localhost + HTTP
end-to-end).

**Baru (M2): hostapdctrl (IF-05a)** — `internal/net/wifi/hostapdctl`:
klien ctrl socket unixgram native Go per BSS (tanpa hostapd_cli).
ATTACH untuk stream event, PING keepalive + re-attach otomatis saat
hostapd restart, `DISASSOCIATE`/`DEAUTHENTICATE` untuk revoke
(§4.6 urutan efek), `STATUS` parsing (FR-WIF-009). Invarian inti yang
diuji: unixgram hanya boleh punya SATU pembaca — pump readEvents
mem-pump socket, reply perintah di-route via waiter channel;
ATTACH pakai jalur inline karena pump belum berjalan. MAC
Dikanonikalisasi lowercase di batas. 6 test `-race` dengan fake
hostapd unixgram (event, keepalive, restart-reconnect, FAIL reply).

**Baru (M2 tuntas): wiring hostapd ↔ dnsmasq** — dua sambungan terakhir
MOD-WIFI/MOD-DHCP kini aktif:

1. **DEAUTH saat revoke (§4.6 urutan efek)** — `netctl.Real` punya seam
   `Deauth` yang dipanggil best-effort SETELAH broker revoke sukses
   (nft dulu, radio belakangan); kegagalan radio tidak menggagalkan
   revoke yang sudah live di kernel. `cmd/kcportald` mengisinya dengan
   klien `hostapdctl` per-BSS (DEAUTHENTICATE ke wlan0/wlan0_1, atau
   wlan0 saja saat `KCP_WIFI_BSS=single`) dan menjalankan task
   `hostapd-ctl` (keepalive/re-attach) + `hostapd-events` (stream
   AP-STA-*, bahan Bouncer di M3). `-dev` tetap tanpa radio sama sekali.
2. **Apply config AP/DHCP otomatis** — saat render menemukan drift,
   kcportald me-restart unit pemiliknya: `hostapd@kcportald` untuk
   hostapd.conf, `dnsmasq-kcp` untuk perubahan pool dnsmasq.conf.
   Reservasi `hosts.d/` tidak lagi memicu SIGHUP berkala — dnsmasq
   mengambilnya via inotify per berkas (`WriteReservations` kini
   melaporkan jumlah perubahan). Karena daemon berjalan sebagai user
   `kcportal`, restart diizinkan aturan polkit sempit
   `deploy/pi/10-kcportal-restart.rules`: hanya dua unit itu, hanya verb
   restart; tanpa rule, kegagalan ter-log dan ops me-restart manual
   seperti sebelumnya (fail-open yang aman — config di disk sudah
   benar).

Dengan ini M2 tuntas; berikutnya M3 (portal tamu + REST admin §5/§7.2):
portal-edge di 10.20.3.1:8080 yang memanggil `netctl.AuthorizeGuest`/
`RevokeGuest` (termasuk DEAUTH radio baru di atas), endpoint
`/api/v1/*`, dan `web/portal` + `web/admin`.

**Terverifikasi live di Pi 5 (2026-09-29)**: revoke tamu lewat
`kcportald -revoke` menendang klien dari radio dalam 3 detik
(station dump 1 → 0) dan MAC hilang dari `authed_guests` via drift
loop; anti-lockout MgmtV4 membuktikan diri (SSH hidup di atas
ruleset penuh). **Batas platform yang ditemukan**: hostapd 2.10 di
radio CYW43455 (Pi 5) tidak mengirim event ctrl `AP-STA-*` sama
sekali — dibuktikan dua listener independen (klien hostapdctl kami
dan `hostapd_cli -a` resmi) sama-sama hanya menerima ATTACH OK tanpa
event saat station connect/disconnect. Konsekuensi: task
`hostapd-events` hanyalah log kosong di hardware ini (bahan Bouncer
M3 tetap jalan lewat neighbor/hook), sedangkan jalur DEAUTH revoke
yang dipakai enforcement tidak terpengaruh.

**Baru (M2): netlink asli (rtnetlink, DD-03)** —
`internal/net/netlink`: klien NETLINK_ROUTE native Go (zero deps —
semua konstanta sudah ada di x/sys/unix). `Dump()` = RTM_GETNEIGH
+NLM_F_DUMP dengan resolusi nama iface via RTM_GETLINK, entri
NUD_NONE/INCOMPLETE/FAILED difilter, MAC kanonik lowercase dari bytes
NDA_LLADDR. `Subscribe()` = bind RTNLGRP_NEIGH, stream RTM_NEWNEIGH
push. `netctl.Real` sekarang dump via netlink (fallback `ip neigh`
tetap ada), watcher neighbors menerima push via `Cache.Merge` (poll 5s
jadi jalur resync), dan setiap apply ruleset / event neighbor menaikkan
counter `NeighRev` (PD-4). Flag ops baru: `kcportald -neigh-dump`.
9 test `-race`, termasuk Dump asli ke kernel dan framing via
netlink userspace pair.

**Baru (M2): jalur produksi penuh di Pi 5 (`kotacloud-captive`)** —
`deploy/pi/README-production.md`: tahapan anti-lockout (infra dulu,
ruleset belakangan). `internal/runtimecfg` merender hostapd.conf +
dnsmasq.conf + hosts.d dari state.db (deterministik, no-churn,
fail-closed saat bridge hilang); `cmd/dhcp-hook` = helper IF-05b
binary; unit `hostapd@kcportald` + `dnsmasq-kcp` memakai config hasil
render; script `kcp-net-apply.sh` (ops, idempoten, `--keep-eth0`)
membuat bridges/gateway; flag `-setup -mgmt-iface eth0` membuat
ruleset penuh aman sejak Tahap 2 (mark 0x01 untuk plane manajemen).
Status terverifikasi di Pi: 3 service `active`+`enabled`, SSID
`portal` mengudara, 4 pool DHCP kanonik, 5 tabel nft terpasang, SSH
tak terputus sepanjang proses. **Batas hardware ditemukan**: radio
CYW43455 Pi 5 hanya `#{ AP } <= 1` (iw list) → DD-01 dual-BSS gagal
EBUSY; fallback `KCP_WIFI_BSS=single` menjalankan BSS guest portal
saja (upgrade: radio kedua di M4+). VHT80 juga ditolak firmware →
HT20 5GHz ch36.

**Baru (M2): netlink asli (rtnetlink, DD-03)** —

## Build & jalankan (di mesinmu, bukan di sandbox saya)

```sh
go mod tidy          # unduh modernc.org/sqlite + gopkg.in/yaml.v3
go build ./...
./kcportald -dev -state ./state.db -config ./app.yaml
```

Tanpa `-dev`, `main.go` sengaja berhenti dengan pesan error — `NetCtl`
asli (nft + netlink) baru masuk di M1/M2, belum ada di M0.

## Struktur

```
cmd/kcportald/          entrypoint proses tunggal (§2.5)
internal/core/          Command · Result · Actor (state actor tunggal, PD-3) · Bus
internal/net/
  netctl/                kontrak IF-01 + Mock
  nft/                   (M1) generator ruleset kcp_zones/kcp_filter/kcp_portal/kcp_nat/kcp_l2
internal/config/        app.yaml
internal/store/         state.db (SQLite) + migrations/0001_base.sql (skema asli)
internal/supervisor/    lifecycle task runner
server/                 (M5) MOD-SERVER — Go net/http + MySQL + Redis
  migrations/0001_kcp_server_mysql.sql   skema MariaDB/MySQL asli (referensi, belum dipakai kode)
web/portal/              (M3) React — portal tamu
web/admin/               (M3) React — GUI admin
web/pos/                 (M4) migrations pos.db (skema asli, dipakai internal/pos/store)
internal/pos/            (M4) store pos.db · pki CA lokal · printer ESC/POS
cmd/pos-cafe             (M4) aplikasi PoS (kontainer rootless)
cmd/pos-proxy            (M4) TLS :8443 → pos-cafe
cmd/pos-onboard          (M4) CA lokal + unduh ca.crt (:8082)
deploy/pi/pos/           (M4) setup, unit, verifikasi (verify-pos.sh)
docs/ROADMAP.md          pembagian milestone + gap yang perlu keputusanmu
docs/M4-plan.md          rencana terperinci M4 PoS App Pack (pos-cafe)
```

## Catatan jujur soal batasan build di sandbox ini

Setiap file di sini sudah lolos `gofmt` dan, untuk paket yang murni
stdlib (`core`, `netctl`, `supervisor`), sudah lolos `go build` +
`go vet` penuh di sandbox. Untuk `internal/config`, `internal/store`,
dan `cmd/kcportald` saya **tidak** bisa menjalankan `go build` end-to-end
di sini karena sandbox ini tidak boleh mengakses proxy modul Go —
jalankan `go build ./...` di mesinmu untuk verifikasi penuh; kalau ada
typo yang lolos `gofmt`, di situ akan langsung ketahuan.
