#!/bin/sh
# kcp-tag.sh — dhcp-script helper for dnsmasq (IF-05b, §4.5).
# Forwards lease events to kcportald's hook.sock as one JSON line.
# Installed at /usr/lib/kcportal/dhcp-hook — referenced by
# dhcp-script= in the generated dnsmasq.conf.
#
# dnsmasq contract: "$1" = add|old|del, "$2" = MAC, "$3" = IP,
# "$4" = hostname; DNSMASQ_INTERFACE carries the source interface.
set -u
SOCK="${KCPORTAL_HOOK_SOCK:-/run/kcportal/hook.sock}"
[ -S "$SOCK" ] || exit 0

ACT="$1"; MAC="$2"; IP="$3"; HOST="$4"
case "$ACT" in add|old|del) ;; *) exit 0 ;; esac

# MAC lowercase canonical at the boundary (state.db invariant).
MAC=$(printf '%s' "$MAC" | tr 'A-Z' 'a-z')

# One JSON object per line, written atomically to the unix socket.
# A dead daemon must not wedge dnsmasq's lease hook: 1 s budget, then go.
printf '{"action":"%s","mac":"%s","ip":"%s","hostname":"%s","interface":"%s"}\n' \
	"$ACT" "$MAC" "$IP" "$HOST" "${DNSMASQ_INTERFACE:-}" |
timeout 1 /usr/bin/socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 ||
printf '{"action":"%s","mac":"%s","ip":"%s","hostname":"%s","interface":"%s"}\n' \
	"$ACT" "$MAC" "$IP" "$HOST" "${DNSMASQ_INTERFACE:-}" >/dev/null 2>&1 ||
exit 0
