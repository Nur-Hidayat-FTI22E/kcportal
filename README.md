# kotacloud-portal

Implementasi bertahap dari `kotacloud-portal-software-design.md`
(SDD-Design v0.1). Lihat `docs/ROADMAP.md` untuk pembagian milestone dan
gap yang perlu keputusanmu sebelum lanjut ke M1.

## Status: M0 — fondasi

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
web/pos/                 (M4) App Pack pos-cafe
  migrations/0001_pos_db.sql             skema pos.db asli (referensi, belum dipakai kode)
docs/ROADMAP.md          pembagian milestone + gap yang perlu keputusanmu
```

## Catatan jujur soal batasan build di sandbox ini

Setiap file di sini sudah lolos `gofmt` dan, untuk paket yang murni
stdlib (`core`, `netctl`, `supervisor`), sudah lolos `go build` +
`go vet` penuh di sandbox. Untuk `internal/config`, `internal/store`,
dan `cmd/kcportald` saya **tidak** bisa menjalankan `go build` end-to-end
di sini karena sandbox ini tidak boleh mengakses proxy modul Go —
jalankan `go build ./...` di mesinmu untuk verifikasi penuh; kalau ada
typo yang lolos `gofmt`, di situ akan langsung ketahuan.
