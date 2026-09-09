#!/bin/bash
# setup_proot.sh — one-time setup of Alpine Linux ARM + gcompat on SMB400.
#
# Run from the development host (requires ADB connection to device):
#   make setup-runtime ADB_TARGET=<device-ip>:5555
#
# What this does:
#   1. Downloads the Alpine Linux ARM minimal rootfs
#   2. Pushes it to /data/local/tmp/ on the device and extracts it
#   3. chroots into the rootfs (adb is root) and installs gcompat via apk
#      (Hotarun's latest release binary `hotarun-linux-arm32` is
#      armv7-unknown-linux-gnueabihf/glibc, so Alpine/musl needs gcompat)
#
# The runtime (start_hotarun.sh) also uses chroot, so no proot is needed.

set -euo pipefail

ADB_TARGET="${1:-}"
if [ -n "$ADB_TARGET" ]; then
    ADB="adb -s $ADB_TARGET"
else
    ADB="adb"
fi

DEVICE_TMP=/data/local/tmp
ROOTFS_DIR="$DEVICE_TMP/hotarun-root"
WORK_DIR=$(mktemp -d)
trap "rm -rf '$WORK_DIR'" EXIT

ALPINE_VERSION=3.20
ALPINE_ARCH=armhf
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"

echo "=== Step 1: Download Alpine ${ALPINE_VERSION} (${ALPINE_ARCH}) ==="
curl -L -o "$WORK_DIR/alpine-rootfs.tar.gz" "$ALPINE_URL"
# Android's toybox tar cannot exec gunzip, so decompress on the host and push
# an uncompressed .tar (extracted with `tar xf` on the device).
gunzip "$WORK_DIR/alpine-rootfs.tar.gz"   # → $WORK_DIR/alpine-rootfs.tar

echo "=== Step 2: Push and extract Alpine rootfs ==="
$ADB shell mkdir -p "$ROOTFS_DIR"
$ADB push "$WORK_DIR/alpine-rootfs.tar" "$DEVICE_TMP/alpine-rootfs.tar"
$ADB shell "cd '$ROOTFS_DIR' && tar xf '$DEVICE_TMP/alpine-rootfs.tar'"
$ADB shell "rm '$DEVICE_TMP/alpine-rootfs.tar'"

echo "=== Step 3: Configure Alpine DNS ==="
$ADB shell "echo 'nameserver 8.8.8.8' > '$ROOTFS_DIR/etc/resolv.conf'"

echo "=== Step 4: Install gcompat inside chroot (for Hotarun glibc binary) ==="
# adb runs as root, so we chroot directly (same mechanism as the runtime).
# proc + /dev are needed for apk (TLS uses /dev/urandom).
$ADB shell '
set -e
ROOTFS=/data/local/tmp/hotarun-root
mount -t proc proc "$ROOTFS/proc" 2>/dev/null || true
mount -o bind /dev "$ROOTFS/dev"  2>/dev/null || true
chroot "$ROOTFS" /bin/sh -c "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; apk update && apk add gcompat libstdc++"
RC=$?
umount "$ROOTFS/dev"  2>/dev/null || true
umount "$ROOTFS/proc" 2>/dev/null || true
exit $RC
'

echo ""
echo "=== Setup complete ==="
echo "Hotarun preflight (Alpine + gcompat ready):"
$ADB shell "chroot '$ROOTFS_DIR' /bin/sh -c 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin; ls /lib/libgcompat* 2>/dev/null || echo gcompat-installed'"
