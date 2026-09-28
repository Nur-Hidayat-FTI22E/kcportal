#!/bin/sh
# e2e-watch.sh — live lab monitor for the E2E laptop test: stations on
# wlan0, dnsmasq leases, lease-hook traffic, authed_guests, and the
# br-guest neighbor view, appended to /tmp/e2e-watch.log every 10 s.
# Usage: sudo /tmp/e2e-watch.sh [seconds]   (default 1800)

DUR="${1:-1800}"
LOG=/tmp/e2e-watch.log
: > "$LOG"
end=$(( $(date +%s) + DUR ))

while [ "$(date +%s)" -lt "$end" ]; do
	{
		echo "=== $(date +%T) ==="
		n=$(/usr/sbin/iw dev wlan0 station dump 2>/dev/null | grep -c "^Station")
		echo "stations: $n"
		[ "$n" -gt 0 ] && /usr/sbin/iw dev wlan0 station dump 2>/dev/null | grep -E "^Station|signal:" | head -6
		echo "leases:"
		cat /run/kcportal/dnsmasq/leases 2>/dev/null | tail -5 || true
		echo "dhcp-events(20s):"
		journalctl -u dnsmasq-kcp --since "20 seconds ago" --no-pager 2>/dev/null |
			grep -E "DHCPDISCOVER|DHCPREQUEST|DHCPACK|allocated" | tail -5 || true
		echo "authed_guests:"
		nft list set inet kcp_portal authed_guests 2>/dev/null | sed -n "/elements/,/}/p" || true
		echo "neigh(br-guest):"
		/usr/sbin/ip neigh show dev br-guest 2>/dev/null | head -4 || true
		echo
	} >> "$LOG" 2>&1
	sleep 10
done
