# Jalur produksi di `kotacloud-captive` — dari `-dev` ke ruleset penuh

Prinsip urutan (anti-lockout): infrastruktur dulu, ruleset terakhir.
Setiap tahap bisa diverifikasi sebelum lanjut, dan semua langkah
idempoten.

## Tahap 0 — pasang artefak (sekali / saat update)

Dari workstation:

```sh
cd project_buf/kotacloud-portal-M0/kotacloud-portal
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o build/kcportald-arm64 ./cmd/kcportald
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o build/dhcp-hook-arm64 ./cmd/dhcp-hook
sshpass -p 'REDACTED' scp build/kcportald-arm64 build/dhcp-hook-arm64 \
  deploy/pi/kcp-net-apply.sh deploy/pi/kcp-tag.sh deploy/pi/kcportald.service \
  deploy/pi/hostapd@kcportald.service deploy/pi/dnsmasq-kcp.service \
  deploy/pi/10-kcportal-restart.rules \
  kotacloud-captive@192.168.100.132:/tmp/
```

Di Pi:

```sh
sudo install -m 0755 /tmp/kcportald-arm64 /usr/local/bin/kcportald
sudo install -m 0755 /tmp/dhcp-hook-arm64 /usr/lib/kcportal/dhcp-hook
sudo install -m 0755 /tmp/kcp-tag.sh /usr/lib/kcportal/dhcp-hook.sh   # fallback non-Go (opsional)
sudo install -m 0644 /tmp/kcportald.service /etc/systemd/system/
sudo install -m 0644 /tmp/hostapd@kcportald.service /etc/systemd/system/
sudo install -m 0644 /tmp/dnsmasq-kcp.service /etc/systemd/system/
sudo install -m 0644 /tmp/10-kcportal-restart.rules /etc/polkit-1/rules.d/
sudo systemctl restart polkit 2>/dev/null || true
sudo apt-get install -y hostapd dnsmasq
sudo systemctl disable --now hostapd.service dnsmasq.service 2>/dev/null || true  # jangan biarkan duel konfigurasi
sudo systemctl daemon-reload
```

## Tahap 1 — bridges + alamat (TIDAK memindah eth0)

```sh
sudo sh /tmp/kcp-net-apply.sh --keep-eth0
ip -br a show br-lan br-guest     # verifikasi 10.20.1.1, 10.20.2.1, 10.20.99.1, 10.20.3.1

# Persistenkan: jalankan ulang otomatis tiap boot. Tanpa ini bridges
# hilang saat reboot dan kcportald fail-closed (render AP/DHCP dilewati,
# hostapd + dnsmasq crash-loop, SSID mati diam-diam).
sudo install -m 0755 /tmp/kcp-net-apply.sh /usr/local/sbin/kcp-net-apply.sh
sudo install -m 0644 /tmp/kcportal-netsetup.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now kcportal-netsetup
```

SSH masih aman: eth0 tidak disentuh.

## Tahap 2 — posture setup: ruleset + render config AP/DHCP

```sh
sudo rm -f /etc/systemd/system/kcportald.service.d/lab-dev.conf
sudo mkdir -p /etc/systemd/system/kcportald.service.d
printf '[Service]\nEnvironment=KCP_STAFF_PSK=GantiPSK-Staff-min-8-karakter\nExecStart=\nExecStart=/usr/local/bin/kcportald -config /etc/kcportal/app.yaml -state /var/lib/kcportal/state.db -nft-dir /run/kcportal -setup -mgmt-iface eth0\n' | \
  sudo tee /etc/systemd/system/kcportald.service.d/setup-lab.conf >/dev/null
# -setup -mgmt-iface eth0 => classify menandai eth0 sebagai 0x01 (admin):
# ruleset PENUH terpasang tapi port 22 tetap accept untuk plane mgmt.
# Produksi: PSK pindah ke settings row staff_psk (M3 admin GUI).
sudo systemctl daemon-reload && sudo systemctl restart kcportald
sleep 3 && sudo nft list ruleset | grep -c 'table' && ls -l /run/kcportal/hostapd.conf /run/kcportal/dnsmasq/
```

kcportald kini merender `hostapd.conf` + `dnsmasq.conf` + `hosts.d/`
dari state.db (deterministik, no-churn). Saat ada perubahan config, dia
me-restart unit pemiliknya sendiri (`hostapd@kcportald` /
`dnsmasq-kcp`) — diizinkan polkit rule dari Tahap 0, hanya untuk dua
unit itu dan hanya verb restart. Reservasi perangkat di `hosts.d/`
diambil dnsmasq via inotify tanpa restart. Revoke tamu (M3 GUI / ops)
kini juga menendang klien dari radio: nft dulu, lalu DEAUTH hostapd
(§4.6) — lihat `sta connected/disconnected` di jurnal.

## Tahap 3 — Wi-Fi & DHCP hidup (ruleset BELUM dipasang)

```sh
sudo systemctl enable --now hostapd@kcportald dnsmasq-kcp
systemctl status hostapd@kcportald dnsmasq-kcp --no-pager | head -20
sudo journalctl -u dnsmasq-kcp -n 10 --no-pager
```

Verifikasi dari laptop: SSID staff/guest muncul, klien dapat lease
(120 s dari pool Waiting bila belum approved — TV-02).

## Tahap 4 — posture produksi penuh (sengaja terakhir)

Posture setup masih menandai eth0 0x01. Produksi penuh berarti mark
admin kembali ke mac_zone (state.db): hapus drop-in setup, dan pastikan
salah satu dulu — (a) eth0 sudah jadi port br-lan dan console tersedia,
atau (b) MAC workstation admin sudah approved di state.db sehingga
mac_zone mengenali plane mgmt.

```sh
sudo rm -f /etc/systemd/system/kcportald.service.d/setup-lab.conf
sudo systemctl daemon-reload && sudo systemctl restart kcportald
sudo journalctl -u kcportald -n 5 --no-pager   # harus: real NetCtl active
sudo nft list ruleset | head -30               # mac_zone aktif, bukan 0x01 statis
```

## Verifikasi DEAUTH revoke (§4.6)

`kcportald -revoke <MAC>` kini menutup sesi di state.db DAN menendang
klien dari radio (DEAUTHENTICATE ke semua BSS via ctrl socket — jalur
one-shot, tanpa ATTACH). Skrip verifikasi menjalankan cek bertahap:

```sh
# dari workstation: build + kirim binary & skrip
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o build/kcportald-arm64 ./cmd/kcportald
sshpass -p 'REDACTED' scp build/kcportald-arm64 deploy/pi/verify-deauth.sh kotacloud-captive@192.168.100.132:/tmp/

# di Pi:
sudo install -m 0755 /tmp/kcportald-arm64 /usr/local/bin/kcportald && sudo systemctl restart kcportald
sudo sh /tmp/verify-deauth.sh                        # cek 1-4: socket, attach, reply OK
sudo sh /tmp/verify-deauth.sh aa:bb:cc:dd:ee:ff      # + cek 6-7: klien live ditendang
```

Cek 6 butuh satu perangkat ter-associate ke SSID guest; berhasil =
`sta disconnected` di jurnal kcportald, deauth di jurnal hostapd, dan
MAC hilang dari set `authed_guests` (drift loop ≤30 s). Varian
hands-free: `test-deauth-live.sh <batas-detik>` menunggu klien join
sendiri, lalu revoke + verifikasi otomatis (nohup, log ke
`/tmp/deauth-live.log`) — dipakai saat verifikasi DEAUTH 2026-09-29.

## Rollback darurat

```sh
sudo nft -f /run/kcportal/last-good.nft        # snapshot commit-confirm (§4.7)
sudo systemctl restart kcportald               # atau:
printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/kcportald -config /etc/kcportal/app.yaml -state /var/lib/kcportal/state.db -nft-dir /run/kcportal -dev\n' | \
  sudo tee /etc/systemd/system/kcportald.service.d/lab-dev.conf >/dev/null && sudo systemctl daemon-reload && sudo systemctl restart kcportald
```
