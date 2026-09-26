# web/pos (M4)

PoS kasir — App Pack `pos-cafe` terpisah, dijalankan Podman rootless
(§7.1 IF-03, DD-14). SQLite `synchronous=FULL`, satu koneksi tulis
(DD-12/ERR-06 — beda dari state.db kcportald yang `synchronous=NORMAL`).
Lihat §6.5 untuk peta migrasi dari prototipe yang sudah divalidasi lokal.

Belum dibangun — dijadwalkan M4 di docs/ROADMAP.md.
