# Rencana M4 — PoS App Pack (pos-cafe)

Status: **RENCANA** (belum dieksekusi). Disusun 2026-09-29 setelah M3
tuntas (REST admin + web GUI + DoH shield). Keputusan pilot yang
mengunci desain (2026-09-29):

- **Printer: USB dan LAN keduanya** diimplementasi (IF-03 env
  `PrinterMode: usb|tcp` — LAN untuk pilot cepat, USB untuk warung
  tanpa jaringan kabel).
- **Pembayaran MVP: cash + QRIS manual** — QRIS/EDC dicatat sebagai
  `reference` saja (skema `payments.method` sudah mendukung
  `cash|qris|other`; SEC-029: tidak pernah ada data kartu).

---

## 0. Gambaran besar

PoS **bukan bagian dari kcportald**. Ia kontainer rootless (Podman) di
dalam unit Pi, berkomunikasi dengan router hanya lewat dua port yang
sudah diizinkan ruleset (`meta mark 0x02 tcp dport { 8443, 8082 }` —
sudah live sejak M1):

```
kasir (br-lan 10.20.2.x)
  └─> :8443  apps proxy  (TLS, SNI pos.<venue>.kcp.internal)  ─> pos-cafe (rootless)
admin ─> :8082  pos-onboard (CA lokal T1, distribusi cert ke browser kasir)
pos-cafe ─> printer USB (/dev/usb/lp0) atau LAN 10.20.2.20:9100
pos-cafe ─> TIDAK ada akses lain (egress di-drop, DD-14)
```

Batasan arsitektur yang tidak boleh dilanggar:

1. **pos.db terpisah dari state.db** (§6.5): kcportald TIDAK membaca
   pos.db; PoS TIDAK menulis state.db. Satu-satunya titik temu yang
   diizinkan M4: tidak ada. (Ringkasan harian ke kcp-server itu M5.)
2. **DD-12/ERR-06**: pos.db `synchronous=FULL`, SATU koneksi tulis.
3. **DD-14**: egress kontainer dibatasi `meta skuid` di chain output
   nftables (placeholder sudah ada di template, §3 `chain output`).
4. **Rootless**: proses PoS berjalan sebagai user `kcapps` (bukan
   kcportal, bukan root); systemd user manager + lingering.

---

## 1. Komponen & deliverable

### M4.1 — Podman + Quadlet fondasi — **SELESAI (2026-09-30)**

- [x] `deploy/pi/pos/pos-setup.sh`: install Podman + uidmap, buat user
  `kcapps` (lingering on), subuid/subgid, direktori
  `/var/lib/kcportal/pos` (data pos.db + CA). Idempotent, gaya sama
  dengan `kcp-net-apply.sh`. *Realitas di Pi: Debian 13 Trixie →
  Podman 5.4.2 → jalur quadlet langsung terpilih; fallback tetap
  dikirim untuk ketahanan.*
- [x] **Deteksi Quadlet** >= 4.4 → quadlet; fallback unit user manual
  (`pos-cafe.service`) tetap disertakan.
- [x] Quadlet `pos-cafe.container` + image offline-first:
  - **Tanpa pull registry sama sekali**: binari dibangun di host Pi,
    `Containerfile` satu stage `FROM scratch` (binari + passwd).
    Build context distage di `/var/lib/kcportal/pos/build` karena
    storage image Podman **per-user** (image milik kotacloud-captive
    tak terlihat oleh kcapps).
  - `Network=host` + `UserNS=keep-id:uid=1000,gid=1000`;
    `Volume=/var/lib/kcportal/pos:/data`; `Restart=on-failure`.
  - **Tanpa healthcheck kontainer** (image scratch tanpa shell/curl);
    liveness = Restart systemd + pandangan proxy M4.2.
  - **Bind loopback saja** (`POS_ADDR=127.0.0.1:8444`) — teramati
    live: posture lab menerima semua dari subnet mgmt, bind 0.0.0.0
    terjangkau langsung dari workstation; loopback menutupnya di
    segala posture (komit d93507b).
- [x] Verifikasi live: unit `active (running)` + `enabled` (Linger=
  yes), `/healthz` 200 via 127.0.0.1, `podman kill` → auto-restart
  OK, 8444 tak terjangkau dari luar (timeout), 3 service router tetap
  sehat.

### M4.2 —apps proxy + pos-onboard (est. 1 sesi)

- [ ] `apps` proxy (binari Go kecil, SATU proyek `cmd/pos-proxy`):
  terminasi TLS SNI `pos.*` di :8443 → forward ke 127.0.0.1:<app-port>
  (pattern cocok untuk app pack berikutnya). Sertifikat dari CA lokal.
- [ ] `pos-onboard` :8082 (binari Go, `cmd/pos-onboard`): generate CA
  T1 lokal (sekali, di `/var/lib/kcportal/pos/ca`), sertifikat server
  untuk `pos.<venue>`, dan halaman unduh root-CA untuk browser kasir
  (HANYA dari br-lan — ruleset sudah membatasi ke mark 0x02).
- [ ] Kontrak cert: SAN = `pos.<venue>.kcp.internal` + `10.20.2.1`;
  rotasi manual via onboard; tidak ada ACME (T1, DD-09 — publik itu
  M6).

### M4.3 — pos-cafe aplikasi (est. 2-3 sesi, bagian terbesar)

- [ ] `cmd/pos-cafe` (Go, di-embed statis web/pos React kecil — pola
  web/admin yang sudah proven):
  - Auth kasir: PIN argon2id (skema `cashiers.pin_hash`), sesi cookie
    HttpOnly, lock otomatis.
  - Shift: buka/tutup (partial unique index `one_open_shift` menolak
    double — sudah diuji di M0), setoran akhir + selisih.
  - Order: katalog per kategori, cart, diskon item-level,
    penomoran struk `YYMMDD-0007` (tabel `counters`, dalam tx).
  - Bayar: cash (tendered → change_given dihitung) + QRIS manual
    (reference bebas, konfirmasi kasir). Idempotency-Key pada
    `POST /orders/{id}/pay` (tabel `idempotency_keys`, request_hash).
  - Void/refund: wajib role `admin` + alasan → `audit_log_pos`.
  - **Koneksi DB**: satu `*sql.DB` dengan `SetMaxOpenConns(1)` untuk
    tulis (DD-12), baca boleh pool terpisah WAL.
- [ ] Driver printer (paket `internal/pos/printer`):
  - `usb`: ESC/POS via `/dev/usb/lp0` — Podman device passthrough
    (`--device /dev/usb/lp0`) + udev rule tag `uaccess` untuk user
    `kcapps` (file rule di `deploy/pi/pos/99-pos-printer.rules`).
  - `tcp`: ESC/POS raw ke `10.20.2.20:9100`.
  - Pemilihan via env `POS_PRINTER=usb|tcp` + `POS_PRINTER_ADDR`
    (dari `config.AppEntry` IF-03 — field sudah ada di app.yaml).
  - **print_jobs**: enqueue dalam TRANSAKSI yang sama dengan payments
    (FR-POS-007); worker retry with backoff, status
    `queued|printed|failed`, `attempts`+`last_error`.
- [ ] Struk: format ESC/POS 58mm (PaperMM dari env), cut + logo
  opsional; reprint dari arsip order.

### M4.4 — Egress enforcement DD-14 (est. ½ sesi)

- [ ] Chain `app_egress` di template nft + `meta skuid` kcapps-uid:
  allow-established, allow printer-LAN `10.20.2.20:9100` bila mode
  tcp, **drop sisanya** (DNS kontainer ikut dnsmasq router? TIDAK —
  PoS tidak butuh DNS: semua target IP literal; resolve dihindari).
- [ ] Ganti komentar placeholder `chain output` dengan jump nyata;
  golden files di-update; test order-guard (drop sebelum accept).
- [ ] Verifikasi negatif: dari dalam kontainer, `curl 1.1.1.1` harus
  gagal (dan justru itu counter DoH shield akan menangkapnya bila
  lewat br-guest — tidak relevan, ini br-lan side).

### M4.5 — Deployment + verifikasi E2E (est. 1 sesi)

- [ ] `deploy/pi/pos/README.md`: langkah urut (setup → build image di
  Pi → install unit → onboard → uji struk).
- [ ] Verifikasi E2E ala M2/M3: buka shift → order → bayar cash →
  struk keluar (LAN dulu, USB menyusul) → cabut daya saat menulis →
  reboot → 0 transaksi hilang (ERR-06/NFR-POS-03) → percobaan egress
  ilegal gagal → `audit_log_pos` terekam void oleh admin.
- [ ] ROADMAP/README di-update; commit per sub-tahap.

---

## 2. Hal yang sengaja TIDAK ada di M4

- Integrasi mesin EDC/QRIS dinamis (QRIS statis milik venue dicetak di
  struk/kasir saja) — M5+ kalau ada mitra pembayaran.
- Sinkronisasi ringkasan penjualan ke kcp-server — M5 (IF-04).
- Multi-venue / cloud config — M5.
- Printer non-ESC/POS (Star-native dsb.) — hanya kalau pilot menuntut.
- TLS publik/ACME — M6 (T2).

## 3. Risiko & mitigasi

| Risiko | Mitigasi |
|---|---|
| Podman 4.3 Bookworm tanpa Quadlet | Fallback unit systemd user manual (M4.1) — jalur utama sampai Trixie |
| USB passthrough rootless rewel (udev/lock) | Driver tcp dulu untuk pilot; USB menyusul di sesi terpisah dengan udev rule teruji |
| `skuid` match butuh cgroup v2 + correct uid mapping | Verifikasi manual `nft list chain inet kcp_filter output`; fallback: izinkan hanya ke IP printer via `ip daddr` |
| TLS SNI di :8443 dari browser Android lama | Onboard menyediakan cert chain; browser modern OK; fallback HTTP-only di br-lan untuk pilot kalau perlu (dicatat di keputusan) |
| Performa Pi 5 (kontainer + router + AP) | pos-cafe idle ~50MB RSS; diukur di M4.5 dengan `systemd-cgtop` |

## 4. Urutan kerja yang diusulkan

M4.1 → M4.4 → M4.2 → M4.3 → M4.5 (egress dulu supaya kontainer lahir
sudah terkurung; aplikasi terakhir karena paling besar). Setiap tahap
commit terpisah dan diuji di Pi sebelum lanjut, pola yang sama dengan
M2/M3.

---

**Status eksekusi: M4.1 selesai (2026-09-30).** Lanjutan: M4.4
(egress `meta skuid`), M4.2 (proxy + onboard), M4.3 (aplikasi PoS),
M4.5 (verifikasi E2E + uji cabut daya).
