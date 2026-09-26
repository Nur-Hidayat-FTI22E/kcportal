# web/portal (M3)

Portal tamu (captive portal) — React, dibangun statis dan di-embed ke
`kcportald` (§5, §7.1 IF-01). Mengidentifikasi tamu lewat tabel neighbor
(DD-10), memanggil `NetCtl.AuthorizeGuest` lewat `portal-edge`, bukan
langsung.

Belum dibangun — dijadwalkan M3 di docs/ROADMAP.md.
