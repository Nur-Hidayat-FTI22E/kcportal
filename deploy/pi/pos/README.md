# PoS App Pack (pos-cafe) — deployment & verification (M4)

Arsitektur: kasir browser → **pos-proxy** (TLS :8443, SNI
`pos.kcp.internal`) → **pos-cafe** (127.0.0.1:8444, kontainer rootless
Podman, uid `kcapps`, egress default-deny DD-14). CA lokal dibuat &
dilayani **pos-onboard** (:8082). pos.db hidup di
`/var/lib/kcportal/pos` (volume kontainer).

## 1. Fondasi (sekali, sebagai root di Pi)

```sh
cd ~/kcportal
sudo deploy/pi/pos/pos-setup.sh
```

Meng-install: podman, user `kcapps` (lingering), subuid, direktori
data + PKI, unit quadlet/user untuk pos-cafe, unit system pos-onboard,
unit user pos-proxy, udev rule printer.

## 2. Binari + image (build ulang setiap rilis)

Dari mesin kerja (cross-compile) lalu salin ke Pi:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o pos-cafe    ./cmd/pos-cafe
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o pos-proxy   ./cmd/pos-proxy
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o pos-onboard ./cmd/pos-onboard
scp pos-cafe pos-proxy pos-onboard Pi:/tmp/
```

Di Pi (root):

```sh
install -m0755 /tmp/pos-onboard /usr/local/bin/ && systemctl restart pos-onboard
install -m0755 /tmp/pos-proxy   /usr/local/bin/
install -m0755 /tmp/pos-cafe    /var/lib/kcportal/pos/build/bin/
chown -R kcapps: /var/lib/kcportal/pos/build /home/kcapps/.config
cd /var/lib/kcportal/pos/build && sudo -u kcapps -H XDG_RUNTIME_DIR=/run/user/$(id -u kcapps) \
  podman build -f Containerfile -t localhost/pos-cafe:m4 .
sudo -u kcapps -H XDG_RUNTIME_DIR=/run/user/$(id -u kcapps) systemctl --user restart pos-cafe pos-proxy
```

## 3. Verifikasi formal (M4.5)

```sh
sudo deploy/pi/pos/verify-pos.sh
```

Cek: unit aktif, `app_egress` terpasang & egress kcapps terblok,
unduh CA, login TLS (trust CA lokal saja), shift→order→pay, print job
queued. **Drill cabut daya** (NFR-POS-03) manual — checklist di akhir
output script.

## 4. Printer

- **LAN** (pilot cepat): sambungkan printer, catat IP-nya, lalu di
  `pos-cafe.container` tambahkan `Environment=POS_PRINTER=tcp` +
  `Environment=POS_PRINTER_ADDR=<ip>:9100`, dan tambahkan allow egress
  di `app.yaml` (`apps: [{id: pos-cafe, printer_mode: tcp,
  printer_addr: <ip>:9100}]`) supaya `app_egress` mengizinkannya.
- **USB**: colok printer, `ls /dev/usb/lp*`, tambahkan di quadlet:
  `Volume=/dev/usb/lp0:/dev/usb/lp0` + `Environment=POS_PRINTER=usb`.
  udev `uaccess` (sudah terpasang) memberi kcapps akses buka device.
- Tidak ada printer? Worker parkir diam — semua job tetap queued,
  tercetak sendiri saat printer muncul.

## 5. Onboarding browser kasir

Dari browser kasir (br-lan/POS plane): buka `http://<ip-pi>:8082/ca.crt`,
install sertifikat sebagai CA terpercaya, lalu bookmark
`https://pos.kcp.internal:8443`. Login PIN default pilot: `admin` /
`kcpadmin-2026` (**ganti sebelum produksi** — hapus env seed di
quadlet setelah kasir lain dibuat).
