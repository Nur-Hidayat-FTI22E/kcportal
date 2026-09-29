# web/portal (M3)

Halaman captive portal tamu — React + Vite + TypeScript, di-embed ke
binary `kcportald` lewat `internal/listen/portaledge/web` (`//go:embed`),
disajikan dari listener portal yang sama (`10.20.3.1:8080`).

Kontrak kawat sama persis dengan halaman Go template yang digantikan:

- `GET /` — shell SPA (tanpa identitas; SPA menanyakan `/state`).
- `GET /state` — JSON status (identitas dari IP sumber → neighbor table,
  DD-10; tidak ada input identitas dari klien).
- `POST /` — form consent (`terms=yes` wajib, marketing opsional,
  voucher opsional) → 303 balik ke `/`.
- Catch-all — probe captive OS (`/generate_204`, dll) → 302 ke `/`.

Perbaikan UX dibanding halaman Go: error terms/voucher kini tampil
inline di halaman (bukan JSON mentah), dan 403 identitas mendapat
layar "hubungkan ulang Wi-Fi" yang ramah.

`__TERMS_VERSION__` di-inject saat build (harus cocok dengan
`portal.Service.TermsVersion`).

## Build

```sh
cd web/portal
npm install
npm run build   # output: internal/listen/portaledge/web/dist/ (di-commit)
```

`dist/` di-commit supaya CI tetap Go-only; Node hanya perlu saat
mengubah halaman.

## Development

```sh
ssh -L 8080:10.20.3.1:8080 kotacloud-captive@<pi>   # tunnel portal
cd web/portal && npm run dev                         # dev server Vite
```

Catatan: `/state` di dev server akan terlihat dari IP workstation
bukan IP tamu — untuk melihat flow lengkap, uji langsung dari HP di
SSID portal.
