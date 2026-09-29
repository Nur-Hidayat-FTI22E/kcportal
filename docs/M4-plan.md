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

### M4.2 — apps proxy + pos-onboard — **SELESAI (2026-09-30)**

- [x] `internal/pos/pki`: CA lokal T1 idempotent — dibuat sekali;
  CA rusak/kadaluarsa = ERROR (re-key harus disengaja, bukan rotasi
  diam-diam). Leaf di-terbitkan/ulang otomatis bila host berubah atau
  mendekati kadaluarsa (horizon 30 hari; batas leaf 825 hari ala iOS).
- [x] `cmd/pos-onboard` :8082 (unit **system**, root): merawat PKI +
  serve `GET /ca.crt` untuk browser kasir. SAN =
  `pos.kcp.internal` + `10.20.1.1` + `10.20.2.1`.
- [x] `cmd/pos-proxy` :8443 (unit **user** kcapps): terminasi TLS
  (MinVersion 1.2) → `127.0.0.1:8444`; 502 JSON saat app mati; hanya
  MEMBACA PKI (error jelas bila onboard belum jalan).
- [x] Kepemilikan PKI: root menulis → `chown` tree ke kcapps (live:
  proxy gagal baca kunci 0600 root sebelum fix ini).
- [x] Verifikasi live: unduh CA 200 dari workstation → HTTPS
  `https://pos.kcp.internal:8443/` 200 dengan **trust CA lokal SAJA**
  → jawaban `pos-cafe skeleton` sampai di browser. 6 unit aktif
  (onboard, proxy, pos-cafe, kcportald, hostapd, dnsmasq).

### M4.3 — pos-cafe aplikasi — **SELESAI (2026-09-30)**

- [x] `internal/pos/store` (pos.db): migrations ter-embed,
  `synchronous=FULL` + SATU koneksi tulis (DD-12/ERR-06); kasir PIN
  argon2id + verifikasi constant-time; shift (unique index DB menolak
  dobel-open — 409); order dengan nomor struk per-hari (YYMMDD-0001)
  di dalam tx; **pembayaran idempoten** (header Idempotency-Key:
  replay mengembalikan respons tersimpan bertanda `replayed`; key baru
  pada order paid = 409) yang meng-commit payment + order→paid +
  **print_jobs** + audit dalam SATU transaksi (FR-POS-007); void
  admin-only dengan alasan ter-audit.
- [x] `internal/pos/printer`: renderer ESC/POS 58mm murni (32 kolom,
  uang rata kanan, non-ASCII dilipat ke '?'); driver usb (/dev/usb/lp*)
  dan tcp raw 9100; worker antrean dengan backoff (kertas habis tidak
  menghentikan penjualan — job tetap queued).
- [x] `cmd/pos-cafe`: sesi cookie HMAC (HttpOnly, SameSite=strict,
  secret per-boot), API JSON login/me/shift/products/orders/items/pay/
  void, seed admin pertama-boot via env.
- [x] Test E2E in-process: seluruh alur + edge (underpay, replay,
  dobel-bayar, izin void, pin salah, cookie di-tamper, printer worker
  race-free) — `go test -race` hijau penuh.
- [x] Verifikasi live di Pi via rantai HTTPS nyata (workstation →
  proxy TLS → pos-cafe): login admin → shift open → order
  `260929-0001` → item → bayar tunai (kembalian 4000) → `print_jobs`
  berisi 1 receipt `queued` (menunggu printer fisik) → audit
  `order_pay` → replay ter-tandai. `pos.db` hidup di volume
  `/var/lib/kcportal/pos`.

### M4.3 — sisa kecil (ikut M4.5)

- [ ] UI kasir React (`web/pos`, di-embed) — API JSON sudah lengkap;
  GUI menyusul dengan pola web/admin.
- [ ] Printer fisik: uji `--device /dev/usb/lp0` passthrough saat
  printer USB tersedia; driver tcp tinggal diarahkan ke IP printer
  sebenarnya (env `POS_PRINTER_ADDR`).
- [ ] Reprint dari arsip order (endpoint + job `reprint`).

### M4.4 — Egress enforcement DD-14 — **SELESAI (2026-09-30)**

- [x] Chain `app_egress` + `meta skuid` dari `Plan.AppEgressUID`
  (app.yaml `apps_uid`, ON di Pi = 1001): `oif lo return` →
  `ct state established,related return` → allows eksplisit → `drop`.
  Allows dirender dari entri printer mode-tcp (hanya IP literal —
  kontainer tak punya resolver); mode-usb tak butuh aturan keluar.
- [x] Golden files + test order-guard + validasi allows (proto/IP/port).
- [x] Verifikasi negatif live: `curl 1.1.1.1` sebagai kcapps →
  timeout terblok, counter `app_egress` naik (4 paket); loopback
  healthz dari uid sama tetap 200.

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

**Status eksekusi (2026-09-30): M4.1 ✅ · M4.4 ✅ · M4.2 ✅.** Rantai
HTTPS penuh terbukti dari workstation: unduh CA (onboard :8082) →
TLS :8443 (proxy, trust CA lokal saja) → pos-cafe :8444 (loopback).
Egress kcapps default-deny dengan bukti counter. **Lanjutan: M4.3**
(aplikasi PoS penuh: auth PIN, shift, order, bayar cash+QRIS manual,
printer ESC/POS usb+tcp, print_jobs dalam transaksi pembayaran),
lalu **M4.5** (E2E + uji cabut daya).
