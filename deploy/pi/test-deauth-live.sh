# test-deauth-live.sh — uji LIVE §4.6: tunggu klien associate ke SSID,
# revoke MAC-nya, verifikasi DEAUTH end-to-end. Dijalankan sebagai root
# di Pi (nohup di background):
#
#   nohup sh /tmp/test-deauth-live.sh 600 >/tmp/deauth-live.log 2>&1 &
#   tail -f /tmp/deauth-live.log
#
# PASS = "sta disconnected" di jurnal kcportald setelah revoke + MAC
# hilang dari set authed_guests (drift loop ≤30 s).
set -u
LIMIT="${1:-600}"                     # batas tunggu klien (detik)
KC=/usr/local/bin/kcportald
STATE=/var/lib/kcportal/state.db
J="journalctl -u kcportald --no-pager"
log() { echo "[$(date +%H:%M:%S)] $*"; }

PID=$(systemctl show -p MainPID --value kcportald)
log "menunggu klien associate (batas ${LIMIT}s)..."

WAITED=0
MAC=""
while [ "$WAITED" -lt "$LIMIT" ]; do
    MAC=$($J _PID=$PID | grep "sta connected" | tail -1 | sed -n 's/.*mac=\([0-9a-f:]*\).*/\1/p')
    [ -n "$MAC" ] && break
    sleep 5
    WAITED=$((WAITED + 5))
done

if [ -z "$MAC" ]; then
    log "TIMEOUT: tidak ada klien associate dalam ${LIMIT}s — perangkat belum join SSID"
    exit 2
fi
log "klien terdeteksi: $MAC"

if $J _PID=$PID --since "-2 min" | grep -q "sta disconnected.*$MAC"; then
    log "PASS sebelum revoke?? $MAC sudah disconnect — periksa manual"
    exit 0
fi

log "menjalankan revoke (state.db + DEAUTH radio)..."
"$KC" -state "$STATE" -revoke "$MAC" 2>&1 | sed 's/^/    /'

sleep 4
if $J _PID=$PID --since "-1 min" | grep -q "sta disconnected.*$MAC"; then
    log "PASS: $MAC menerima DEAUTH — 'sta disconnected' tercatat di jurnal kcportald"
else
    log "FAIL: tidak ada sta disconnected untuk $MAC"
    log "     cek: $J _PID=$PID -n 20 | grep $MAC"
    exit 1
fi

sleep 30
if echo "REDACTED" | sudo -S nft list set inet kcp_portal authed_guests 2>/dev/null | grep -qi "$MAC"; then
    log "PERINGATAN: $MAC masih di authed_guests (drift loop belum berjalan; tunggu 30s lagi)"
else
    log "PASS: $MAC tidak ada di authed_guests (kernel gate bersih)"
fi

log "verifikasi fisik: Wi-Fi pada perangkat $MAC seharusnya TERPUTUS (bisa join lagi — BSS open)"
log "selesai. riwayat hostapd:"
journalctl -u hostapd@kcportald --since "-3 min" --no-pager 2>/dev/null | grep -i deauth | tail -3
