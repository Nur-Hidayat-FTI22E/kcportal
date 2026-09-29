# web/admin (M3)

Web GUI admin — React + Vite + TypeScript, di-embed ke binary `kcportald`
lewat `internal/api/webadmin` (`//go:embed`), disajikan dari listener REST
yang sama (`127.0.0.1:8083`, §7.2): shell statis tanpa token (halaman
login harus bisa dimuat dulu), semua `/api/*` tetap bearer-token.

Fitur: setup wizard `/network/wan`, devices (approve/block), sesi tamu
(revoke), voucher (generate/list), zona + policy (commit-confirm via
banner `/changes/pending`), audit log.

## Build

```sh
cd web/admin
npm install
npm run build   # output: internal/api/webadmin/dist/ (di-commit)
```

`dist/` sengaja di-commit supaya CI dan `go build ./...` tetap Go-only —
Node hanya perlu saat mengubah GUI. Aset di-hash Vite; hanya
`index.html` yang `Cache-Control: no-store`.

## Development

```sh
ssh -L 8083:127.0.0.1:8083 kotacloud-captive@<pi>   # tunnel API
cd web/admin && npm run dev                          # proxy /api -> 8083
```
