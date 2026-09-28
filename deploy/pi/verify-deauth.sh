# verify-deauth.sh — verifikasi end-to-end jalur DEAUTH revoke (§4.6) di
# Pi: infrastruktur dulu (socket + attach + reply), uji live klien belakangan.
#
# Pemakaian (di Pi, sebagai root):
#   sh verify-deauth.sh                      # cek 1-4: tanpa klien Wi-Fi
#   sh verify-deauth.sh aa:bb:cc:dd:ee:ff    # + cek 6: klien live ditendang
#
# Prasyarat: kcportald build >= Sep 2026 (wiring hostapdctl), unit
# hostapd@kcportald aktif, dan untuk cek 6 satu perangkat ter-associate
# ke SSID guest.
set -u

J="journalctl --no-pager"
KC=/usr/local/bin/kcportald
STATE=/var/lib/kcportal/state.db

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "OK: $*"; }

echo "== 1. service aktif"
systemctl is-active kcportald >/dev/null || fail "kcportald tidak aktif"
systemctl is-active hostapd@kcportald >/dev/null || fail "hostapd@kcportald tidak aktif"
pass "kcportald + hostapd@kcportald aktif"

echo "== 2. ctrl socket hostapd"
ls /run/kcportal/hostapd/ || fail "ctrl socket tidak ada (hostapd.conf salah / hostapd gagal attach)"
pass "ctrl socket ada"

echo "== 3. daemon attach"
$J -u kcportald -n 300 | grep -q "hostapd attached" || fail "kcportald belum attach — cek: $J -u kcportald -n 20"
pass "kcportald attached ke ctrl socket"

echo "== 4. oneshot DEAUTH (tanpa klien: hostapd tetap jawab OK)"
out=$("$KC" -state "$STATE" -revoke 00:11:22:33:44:55 2>&1)
case "$out" in
  *"radio deauth failed"*) fail "oneshot deauth gagal: $out" ;;
esac
pass "DEAUTHENTICATE terkirim, hostapd menjawab OK (dial -> cmd -> reply beres)"

echo "== 5. stream event 10 menit terakhir (informasi)"
$J -u kcportald --since "-10 min" | grep -E "sta (dis)?connected" | tail -3

if [ $# -ge 1 ]; then
  MAC="$1"
  echo "== 6. uji LIVE: klien $MAC"
  echo "   pastikan perangkat TERHUBUNG ke SSID guest sekarang (enter untuk lanjut)"
  read -r _
  $J -u kcportald --since "-2 min" | grep -q "sta connected.*$MAC" \
    || echo "   PERINGATAN: 'sta connected $MAC' tidak ada di 2 menit terakhir"
  "$KC" -state "$STATE" -revoke "$MAC"
  sleep 3
  if $J -u kcportald --since "-1 min" | grep -q "sta disconnected.*$MAC"; then
    pass "$MAC menerima DEAUTH (sta disconnected di jurnal kcportald)"
  else
    fail "$MAC tidak terlihat disconnect — cek bss list: $J -u kcportald -n 20"
  fi
  $J -u hostapd@kcportald --since "-1 min" | grep -qi deauth \
    && pass "hostapd mencatat deauth $MAC"
  echo "== 7. sisi kernel (drift loop ≤30s)"
  nft list set inet kcp_portal authed_guests | grep -qi "$MAC" \
    && echo "   PERINGATAN: $MAC masih di authed_guests (tunggu 30s, ulangi)" \
    || pass "authed_guests bersih dari $MAC"
  echo "   verifikasi fisik: Wi-Fi perangkat terputus, lalu bisa join lagi (BSS open)"
fi

echo "== selesai"
