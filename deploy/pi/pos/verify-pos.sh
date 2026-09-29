#!/bin/sh
# verify-pos.sh — formal M4.5 E2E verification for the PoS App Pack.
# Run ON the Pi as root:  sudo deploy/pi/pos/verify-pos.sh
# Safe to re-run (leaves one verification shift/order in pos.db).
# Exit 0 = all automated checks pass. The power-cut drill
# (NFR-POS-03) is interactive — the checklist prints at the end.
set -u
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { # check <label> <command...>
	label="$1"; shift
	if "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi
}

XR="sudo -u kcapps -H XDG_RUNTIME_DIR=/run/user/$(id -u kcapps)"

echo "== 1) unit status =="
check "pos-onboard active"        systemctl is-active pos-onboard
check "kcportald active"          systemctl is-active kcportald
check "hostapd active"            systemctl is-active hostapd@kcportald
check "dnsmasq-kcp active"        systemctl is-active dnsmasq-kcp
check "pos-cafe (user) active"    sh -c "$XR systemctl --user is-active pos-cafe.service | grep -qx active"
check "pos-proxy (user) active"   sh -c "$XR systemctl --user is-active pos-proxy.service | grep -qx active"

echo "== 2) DD-14 egress =="
check "app_egress chain present"  nft list chain inet kcp_filter app_egress
# Egress from uid kcapps must die (timeout); loopback must live.
if $XR timeout 6 curl -s -o /dev/null --max-time 5 http://1.1.1.1/ 2>/dev/null; then
	bad "egress kcapps HARUS terblok (curl 1.1.1.1 berhasil?!)"
else
	ok "egress kcapps terblok (curl 1.1.1.1 timeout)"
fi
if $XR curl -s -m 3 http://127.0.0.1:8444/healthz | grep -q ok; then
	ok "loopback pos-cafe dari uid kcapps hidup"
else
	bad "loopback pos-cafe dari uid kcapps mati"
fi

echo "== 3) CA + TLS (trust CA lokal saja) =="
CA=/tmp/verify-pos-ca.crt
check "unduh ca.crt dari onboard" sh -c "curl -s -m 5 -o '$CA' http://127.0.0.1:8082/ca.crt && test -s '$CA'"
LOGIN=$(curl -s -m 6 --cacert "$CA" --resolve pos.kcp.internal:8443:127.0.0.1 \
	-H "Content-Type: application/json" -d '{"name":"admin","pin":"kcpadmin-2026"}' \
	https://pos.kcp.internal:8443/api/login)
echo "$LOGIN" | grep -q '"ok":true' && ok "login via TLS 8443 (CA lokal dipercaya)" || bad "login TLS: $LOGIN"

echo "== 4) alur jual (shift→order→item→pay) =="
CJ=/tmp/verify-pos.cookies
B="https://pos.kcp.internal:8443"
R() { curl -s -m 6 --cacert "$CA" --resolve pos.kcp.internal:8443:127.0.0.1 -b "$CJ" "$@"; }
curl -s -m 6 --cacert "$CA" --resolve pos.kcp.internal:8443:127.0.0.1 -c "$CJ" \
	-H "Content-Type: application/json" -d '{"name":"admin","pin":"kcpadmin-2026"}' \
	$B/api/login >/dev/null
SHIFT=$(R -H "Content-Type: application/json" -d '{"opening_cash":0}' -X POST $B/api/shift/open 2>/dev/null)
ORDER=$(R -H "Content-Type: application/json" -d '{"table":"VERIFY"}' -X POST $B/api/orders)
OID=$(echo "$ORDER" | grep -o '"order_id":[0-9]*' | cut -d: -f2)
if [ -n "$OID" ]; then
	ok "order dibuat (id=$OID)"
	R -H "Content-Type: application/json" -d '{"product_id":1,"qty":1}' -X POST $B/api/orders/$OID/items >/dev/null
	PAY=$(R -H "Content-Type: application/json" -H "Idempotency-Key: verify-$(date +%s)" \
		-d '{"method":"cash","amount":18000,"tendered":20000}' -X POST $B/api/orders/$OID/pay)
	echo "$PAY" | grep -q '"change":2000' && ok "bayar tunai (kembalian 2000)" || bad "pay: $PAY"
else
	# Shift mungkin sudah terbuka oleh operasional — hanya lapor.
	bad "order gagal (shift terbuka? coba lagi setelah verify awal): $SHIFT $ORDER"
fi

echo "== 5) print job =="
JOB=$(python3 -c "import sqlite3;c=sqlite3.connect('file:/var/lib/kcportal/pos/pos.db?mode=ro',uri=True);print(c.execute('SELECT COUNT(*) FROM print_jobs WHERE status=\"queued\"').fetchone()[0])" 2>/dev/null)
if [ "${JOB:-0}" -ge 1 ]; then ok "print_jobs queued >= 1 (printer fisik belum wajib)"; else bad "tidak ada print job queued"; fi

echo
echo "== HASIL: $PASS pass, $FAIL fail =="
cat <<'DRILL'
== Drill cabut daya (NFR-POS-03, manual, sekali saat pilot) ==
 1. Buka shift + 1 order berbayar (struk queued/tercetak).
 2. CABUT daya Pi TANPA shutdown.
 3. Nyalakan lagi; tunggu semua unit naik (kcportald, pos-cafe, proxy).
 4. sqlite3 /var/lib/kcportal/pos/pos.db \
      "SELECT id,status,total FROM orders ORDER BY id DESC LIMIT 3;"
    → order yang terbayar SEBELUM cabut harus tetap 'paid' (0 transaksi hilang).
 5. Login ulang kasir (sesi memang hilang — secret per-boot), shift lama
    masih terbuka; lanjut jualan.
DRILL
rm -f "$CA" "$CJ"
[ "$FAIL" -eq 0 ]
