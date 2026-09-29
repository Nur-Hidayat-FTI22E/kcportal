#!/bin/sh
# pos-setup.sh — ONE-TIME (idempotent) host preparation for the PoS
# App Pack (M4.1, docs/M4-plan.md). Run by the OPERATOR as root on the
# Pi:  sudo ./pos-setup.sh
#
# What it does:
#   1) installs podman (Debian package) if missing
#   2) creates the kcapps user (system, no login) with lingering so
#      its systemd --user manager runs at boot without a session
#   3) subuid/subgid for rootless userns (keep-id)
#   4) /var/lib/kcportal/pos owned by kcapps (pos.db lives there in
#      M4.3; the volume mount needs it to pre-exist)
#   5) installs the unit: quadlet (Podman >= 4.4) or the plain user
#      unit fallback (Bookworm's 4.3 — the guaranteed path)
#   6) udev tag for the USB receipt printer (/dev/usb/lp*): uaccess so
#      the rootless container (keep-id -> kcapps) can open the device
#
# It never starts the container itself: build the image first
# (build-pos-image.sh), then enable the unit (printed at the end).
set -eu

KCAPPS_USER=kcapps
KCAPPS_UID=1001        # host uid; keep-id maps it to 1000 inside
POS_DIR=/var/lib/kcportal/pos
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"   # script is deploy/pi/pos/… → repo root is 3 up

cmd() { echo "+ $*"; "$@"; }

# --- 1) podman ---
if ! command -v podman >/dev/null 2>&1; then
	cmd apt-get update
	cmd apt-get install -y podman uidmap
fi
PODMAN_MAJOR="$(podman --version | sed -E 's/podman version ([0-9]+)\..*/\1/')"
PODMAN_MINOR="$(podman --version | sed -E 's/podman version [0-9]+\.([0-9]+)\..*/\1/')"
echo "== podman $(podman --version | cut -d' ' -f3) =="

# --- 2) kcapps user + lingering ---
if ! id "$KCAPPS_USER" >/dev/null 2>&1; then
	cmd useradd --system --uid "$KCAPPS_UID" --home-dir /home/kcapps \
		--create-home --shell /usr/sbin/nologin "$KCAPPS_USER"
fi
cmd loginctl enable-linger "$KCAPPS_USER"

# --- 3) subuid/subgid (rootless userns) ---
if ! grep -q "^$KCAPPS_USER:" /etc/subuid 2>/dev/null; then
	cmd usermod --add-subuids 165536-196607 --add-subgids 165536-196607 "$KCAPPS_USER"
fi

# --- 4) data dir ---
cmd mkdir -p "$POS_DIR"
cmd chown "$KCAPPS_USER:$KCAPPS_USER" "$POS_DIR"
cmd chmod 0750 "$POS_DIR"
# pos-onboard's PKI dir must pre-exist: its unit's ReadWritePaths is
# set up before any process runs (missing path → exit 226).
cmd mkdir -p "$POS_DIR/pki"
cmd chmod 0700 "$POS_DIR/pki"

# --- 5b) M4.2 binaries + units (onboard=system, proxy=kcapps user) ---
if [ -f "$REPO_DIR/pos-proxy" ]; then
	cmd install -m 0755 "$REPO_DIR/pos-proxy" /usr/local/bin/pos-proxy
	cmd install -m 0755 "$REPO_DIR/pos-onboard" /usr/local/bin/pos-onboard
	cmd install -m 0644 "$REPO_DIR/deploy/pi/pos/pos-onboard.service" /etc/systemd/system/pos-onboard.service
	cmd systemctl daemon-reload
	cmd systemctl enable --now pos-onboard
	cmd mkdir -p "/home/$KCAPPS_USER/.config/systemd/user"
	cmd install -m 0644 "$REPO_DIR/deploy/pi/pos/pos-proxy.service" "/home/$KCAPPS_USER/.config/systemd/user/pos-proxy.service"
	cmd chown -R "$KCAPPS_USER:$KCAPPS_USER" "/home/$KCAPPS_USER/.config"
	cmd systemctl enable --global pos-proxy 2>/dev/null || true
	# Wait for the PKI to exist before the proxy's first start attempt.
	sleep 2
	cmd systemctl start pos-onboard 2>/dev/null || true
fi

# --- 5) unit install (quadlet vs fallback) ---
if [ "$PODMAN_MAJOR" -gt 4 ] || { [ "$PODMAN_MAJOR" -eq 4 ] && [ "$PODMAN_MINOR" -ge 4 ]; }; then
	echo "== Podman >= 4.4 detected — installing the quadlet fast-path =="
	cmd mkdir -p "/home/$KCAPPS_USER/.config/containers/systemd"
	cmd install -m 0644 "$REPO_DIR/deploy/pi/pos/pos-cafe.container" \
		"/home/$KCAPPS_USER/.config/containers/systemd/pos-cafe.container"
	UNIT_KIND=quadlet
	ENABLE_CMD="systemctl --user enable --now pos-cafe.service"
else
	echo "== Podman < 4.4 detected — installing the user-unit fallback =="
	cmd mkdir -p "/home/$KCAPPS_USER/.config/systemd/user"
	cmd install -m 0644 "$REPO_DIR/deploy/pi/pos/pos-cafe.service" \
		"/home/$KCAPPS_USER/.config/systemd/user/pos-cafe.service"
	UNIT_KIND=fallback
	ENABLE_CMD="systemctl --user enable --now pos-cafe.service"
fi
cmd chown -R "$KCAPPS_USER:$KCAPPS_USER" "/home/$KCAPPS_USER/.config"

# --- 6) udev tag for the USB printer (harmless when none attached) ---
cmd install -m 0644 "$REPO_DIR/deploy/pi/pos/99-pos-printer.rules" /etc/udev/rules.d/99-pos-printer.rules
cmd udevadm control --reload 2>/dev/null || true

echo
echo "== pos-setup done (unit: $UNIT_KIND) =="
echo "Next steps, as root:"
echo "  1. deploy/pi/pos/build-pos-image.sh        # build the image"
echo "  2. sudo -u $KCAPPS_USER -H XDG_RUNTIME_DIR=/run/user/$(id -u $KCAPPS_USER) $ENABLE_CMD"
echo "  3. verify: curl http://127.0.0.1:8444/healthz"
