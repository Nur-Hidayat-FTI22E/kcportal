# Deploy kcportald ke Raspberry Pi 5 (`kotacloud-captive`)

Target: `kotacloud-captive` — Raspberry Pi 5 (arm64, Raspberry Pi OS
bookworm), alamat LAN `192.168.100.132`, user `kotacloud-captive`,
password `REDACTED` (kredensial lab — ganti sebelum produksi).

Daemon berjalan sebagai user khusus `kcportal` dengan `CAP_NET_ADMIN`
(rtnetlink + `nft -c/-f`) dan `CAP_NET_RAW` (`conntrack -D`,
best-effort). Tanpa `-dev`: nft netlink `NETLINK_NETFILTER` aktif penuh.

## 0. Siapkan Pi (sekali)

```bash
sudo useradd --system --home /var/lib/kcportal --shell /usr/sbin/nologin kcportal || true
sudo mkdir -p /etc/kcportal
sudo apt-get install -y nftables conntrack   # dnsmasq/hostapd menyusul di M2+
```

Unit systemd sengaja TIDAK menyalakan `nftables.service` — satu-satunya
penulis ruleset adalah kcportald (DD-04). Pastikan service bawaan tidak
menganggu: `sudo systemctl disable --now nftables.service`.

## 1. Build dari workstation

```bash
cd project_buf/kotacloud-portal-M0/kotacloud-portal
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
  -o build/kcportald-arm64 ./cmd/kcportald
```

## 2. Transfer & pasang

```bash
sshpass -p 'REDACTED' scp build/kcportald-arm64 deploy/pi/kcportald.service deploy/pi/app.yaml \
  kotacloud-captive@192.168.100.132:/tmp/

ssh kotacloud-captive@192.168.100.132
sudo install -m 0755 /tmp/kcportald-arm64 /usr/local/bin/kcportald
sudo install -m 0644 /tmp/kcportald.service /etc/systemd/system/kcportald.service
sudo install -m 0644 /tmp/app.yaml /etc/kcportal/app.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now kcportald
```

> `sshpass` hanya ada di workstation lab; di Pi sendiri tidak dibutuhkan.

## 3. Verifikasi

```bash
systemctl status kcportald
sudo journalctl -u kcportald -f
sudo nft list ruleset                 # tabel kcp_zones / kcp_portal / kcp_filter / kcp_nat / kcp_l2
cat /run/kcportal/kcp.nft             # ruleset hasil generator (deterministik)
cat /run/kcportal/last-good.nft       # snapshot commit-confirm
```

Log normal saat boot: `real NetCtl active — neighbor table via rtnetlink`,
lalu `kcportald M1 running — reconciler active`. Kalau `initial ruleset
apply failed`, jalankan manual `sudo /usr/local/bin/kcportald ...` untuk
melihat error `nft -c` apa adanya.

## 4. Rollback darurat

Commit-confirm (§4.7): perubahan berisiko menulis
`/run/kcportal/pending.json` + snapshot `last-good.nft`; tanpa konfirmasi
60 s, daemon mengembalikan snapshot saat restart. Untuk rollback manual:

```bash
sudo nft -f /run/kcportal/last-good.nft
```

## Catatan

- `MemoryMax=128M` sesuai ROADMAP; `WatchdogSec` sengaja belum di-set —
  butuh sd_notify ping yang belum diimplementasikan daemon.
- `-dev` TIDAK dipakai di unit ini (Mock + DryRun hanya untuk debugging
  di workstation).
- Dnsmasq/hostapd (M2) belum dilayani daemon; Wi-Fi dan DHCP masih
  konfigurasi manual sampai milestone berikutnya.
