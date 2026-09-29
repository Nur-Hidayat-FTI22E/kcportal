#!/bin/sh
# build-pos-image.sh — build the pos-cafe container image ON the Pi,
# fully offline: stage the prebuilt linux/arm64 binary + passwd into a
# temp build context, then `podman build` a FROM-scratch image (no
# registry involved). Run from the repo root:
#
#   deploy/pi/pos/build-pos-image.sh
#
# Idempotent: re-running rebuilds the same tag localhost/pos-cafe:m4.
set -eu
cd "$(dirname "$0")"

echo "== 1) build pos-cafe (host toolchain, CGO off for scratch) =="
( cd ../../.. && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" -o "$(pwd)/deploy/pi/pos/bin/pos-cafe" ./cmd/pos-cafe )

echo "== 2) assemble image (FROM scratch, nothing pulled) =="
podman build -f Containerfile -t localhost/pos-cafe:m4 .

echo "== done. Next: pos-setup.sh (user + unit), then =="
echo "   sudo -u kcapps -H systemctl --user enable --now pos-cafe"
