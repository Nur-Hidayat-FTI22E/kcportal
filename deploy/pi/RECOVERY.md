# PEMULIHAN Pi (`kotacloud-captive`) — akses fisik diperlukan SEKALI

**Status**: Pi sedang tidak bisa di-SSH (lockout oleh ruleset — bug
analisis yang sudah diperbaiki di kode: rule `MgmtV4` kini meng-accept
subnet manajemen SEBELUM lompatan WAN di chain input).

**Gejala**: ping/SSH ke 192.168.100.132 timeout dari workstation.

## Langkah Anda (±1 menit, di depan Pi dengan keyboard + monitor)

1. Login di konsol Pi: user `kotacloud-captive`, password `REDACTED`.
2. Jalankan TIGA perintah ini:

```sh
echo 'REDACTED' | sudo -S nft flush ruleset
echo 'REDACTED' | sudo -S systemctl stop kcportald
echo 'REDACTED' | sudo -S sysctl -w net.ipv4.ip_forward=1
```

(`flush ruleset` di sini hanya pemulihan darurat; daemon tidak sedang
berjalan jadi tidak ada yang memasang ulang — DD-04 tetap terjaga untuk
jalur normal.)

Setelah itu SSH dari workstation menyala lagi — **kabari saya**, sisanya
saya kerjakan remote: deploy binary dengan perbaikan anti-lockout +
`ip_forward`, verifikasi HP Anda dapat internet, lalu uji revoke.

## Catatan pemulihan 2026-09-28

Flush ruleset berhasil (port 22 langsung terbuka), tapi baris
`authorized_keys` yang ditempel manual di konsol rusak (spasi antara
`ssh-ed25519` dan base64 hilang saat paste tty) — pubkey ditolak sshd.
Pelajaran: kalau harus menambah kunci dari konsol, validasi langsung
setelah paste dengan `ssh-keygen -lf ~/.ssh/authorized_keys`; kalau
tertulis "is not a valid public key", paste-nya korup.

## Catatan pemulihan 2026-10-01 — SSID mati diam-diam pasca reboot

**Gejala**: device "terhubung" ke `kotacloud-test` tapi tidak pernah
dapat IP, portal tidak muncul, neverssl.com gagal. Dari Pi: `wlan0
DOWN`, `br-guest` tidak ada, `hostapd@kcportald` + `dnsmasq-kcp`
crash-loop (`restart counter 10.600+`), statusnya "activating" —
kelihatan sehat dari daftar service tapi AP sebenarnya mati.

**Akar**: bridges + alamat gateway hanya dibuat SEKALI oleh
`kcp-net-apply.sh` (state kernel, tidak persisten). Reboot 2026-09-30
17:51 menghapusnya; kcportald fail-closed (benar) melewatkan render
hostapd/dnsmasq sehingga ExecStartPre `test -f` kedua unit gagal
selamanya. Bonus bug: registrasi task render hanya dicek bridges saat
startup, jadi bridge yang dibuat belakangan tidak pernah diproses —
sudah diperbaiki (probe ulang tiap tick 30 dtk, self-healing).

**Perbaikan permanen** (sudah diterapkan di Pi):

```sh
sudo install -m 0755 deploy/pi/kcp-net-apply.sh /usr/local/sbin/kcp-net-apply.sh
sudo install -m 0644 deploy/pi/kcportal-netsetup.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now kcportal-netsetup
```

**Verifikasi cepat setelah reboot** (semua harus "active" + AP ENABLED):

```sh
systemctl is-active kcportal-netsetup kcportald hostapd@kcportald dnsmasq-kcp
hostapd_cli -p /run/kcportal/hostapd -i wlan0 status | grep -E "state|freq"
ip -br a show br-guest   # 10.20.3.1/24
```

**Pelajaran monitoring**: `systemctl is-active kcportald` saja TIDAK
cukup untuk menyatakan portal sehat — cek lapisan AP-nya juga
(hostapd_cli status / all_sta), karena kegagalan tinggal di unit
anak yang crash-loop.

## Lanjutan insiden (same night): tamu dapat IP tapi portal tak terjangkau

Setelah bridge pulih, HP dapat lease `10.20.3.x` tapi tetap tidak bisa
membuka apa pun. Diagnosa via tamu sintetis (netns+veth di br-guest,
`/tmp/gsim-*.sh` di Pi) + `nft monitor trace` menemukan DUA bug lagi:

1. **Anti-spoof demotion di setup mode** (SEC-012): rule
   `ip saddr . ether saddr != @mac_ip4 → mark 0x00` tetap dirender
   padahal `mac_ip4` kosong di `-setup` (DD-15 skip bindings). Semua
   paket tamu pasca-DHCP ter-demotion ke mark Waiting dan dibuang
   `input_waiting` (drop). DHCP lolos hanya karena src `0.0.0.0`
   dikecualikan. Fix: rule hanya dirender di mode produksi penuh
   (`render.go` + golden setup + test regresi
   `TestSetupModeSkipsAntiSpoofDemotion`).

2. **Default `-state` CLI salah**: `kcportald -approve` menulis ke
   `/data/kcportal/state.db` (default lama) sementara daemon baca
   `/var/lib/kcportal/state.db` — approve/revoke CLI "sukses" tapi
   `authed_guests` tidak pernah berubah. Fix: default disamakan dengan
   unit systemd.

Verifikasi akhir via gsim (semua PASS): DNS by-name → probe 302 →
portal shell 200 → approve masuk `authed_guests` → HTTP 200 asli
lewat masquerade → revoke → kembali terkunci.

**Teknik diagnosa yang terbukti** (pakai lagi kalau perlu): tamu
sintetis netns+veth + `nft monitor trace` + tcpdump br-guest/eth0
bersamaan — memisahkan masalah L2/L3/nft/uplink tanpa perlu HP.
