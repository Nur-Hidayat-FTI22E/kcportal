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
