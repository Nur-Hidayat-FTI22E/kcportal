#!/bin/sh
# kcp-net-apply.sh — ONE-TIME (idempotent) interface setup for the
# production interface plan (SDD §2.4/§4.1). Run by the OPERATOR, never
# by kcportald: this is the step able to cut management access, so it is
# manual and reviewed (DD-15 spirit). Designed for the lab first:
#
#   sudo ./kcp-net-apply.sh --keep-eth0
#
# --keep-eth0  eth0 stays on the LAN as the management plane (no IP
#              move, no bridge port). Production (Café) wiring instead
#              moves eth0 into br-lan (br-lan then takes the ISP/uplink
#              role per §4.1) — run WITHOUT the flag only when the Pi is
#              on a console/keyboard or you accept re-plugging.
#
# After this script, kcportald's bridge probe (fail-closed) passes and
# the full nft ruleset can be installed safely: classify sees br-lan /
# br-guest, and with --keep-eth0 eth0 keeps an unclassified path for
# SSH by design.
#
# Everything is idempotent: re-running converges to the same state.

set -eu
KEEP_ETH0=0
[ "${1:-}" = "--keep-eth0" ] && KEEP_ETH0=1

cmd() { echo "+ $*"; "$@"; }

# --- 0) the router role needs forwarding on (Raspberry Pi OS ships it
#         disabled — without it guests NEVER reach the internet, ruleset
#         or no ruleset) ---
cmd sysctl -w net.ipv4.ip_forward=1

# --- 1) bridges (DD-01 pairing lives in hostapd; the kernel just needs
#         the devices to exist) ---
if ! ip link show br-guest >/dev/null 2>&1; then
	cmd ip link add br-guest type bridge
fi
cmd ip link set br-guest up
cmd ip addr replace 10.20.3.1/24 dev br-guest

if ! ip link show br-lan >/dev/null 2>&1; then
	cmd ip link add br-lan type bridge
fi
cmd ip link set br-lan up

# --- 2) per-zone gateway addresses on br-lan (§4.1: admin/pos ride the
#         same L2, different subnets) ---
cmd ip addr replace 10.20.1.1/24 dev br-lan
cmd ip addr replace 10.20.2.1/24 dev br-lan
# Waiting gateway (ERR-01) — the router itself is 10.20.99.1.
cmd ip addr replace 10.20.99.1/24 dev br-lan

# --- 3) eth0 handling ---
if [ "$KEEP_ETH0" = "1" ]; then
	echo "== --keep-eth0: eth0 stays the management plane (lab mode) =="
else
	if ip link show eth0 >/dev/null 2>&1 && ! ip link show eth0 | grep -q master; then
		echo "== moving eth0 into br-lan (PRODUCTION wiring; make sure you have console access) =="
		cmd ip link set eth0 down
		cmd ip link set eth0 master br-lan
		cmd ip link set eth0 up
	fi
fi

# --- 4) Wi-Fi radio must be unblocked before hostapd can claim it ---
command -v rfkill >/dev/null 2>&1 && cmd rfkill unblock wifi || true

echo "== bridge summary =="
ip -br addr show br-lan br-guest 2>/dev/null || true
ip -br link show 2>/dev/null | grep -E '^(eth0|wlan0|br-lan|br-guest)' || true
echo "== done. Next: restart kcportald (it will render hostapd/dnsmasq config),"
echo "   then install the production ruleset by removing the -dev drop-in: =="
echo "   sudo rm /etc/systemd/system/kcportald.service.d/lab-dev.conf && sudo systemctl daemon-reload && sudo systemctl restart kcportald"
