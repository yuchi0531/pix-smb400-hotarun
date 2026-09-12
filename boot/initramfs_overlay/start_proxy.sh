#!/system/bin/sh
# start_proxy.sh — start Hotarun on SMB400 via chroot + Alpine ARM32 (auto-start version).
#
# Requires root (ADB shell is root by default on SMB400).
# Alpine rootfs + gcompat must be set up first (see setup_proot.sh).
# Hotarun binary must be deployed first (see `make deploy-hotarun` which
# fetches https://github.com/yuchi0531/Hotarun/releases/latest/download/hotarun-linux-arm32).

ROOTFS=/data/local/tmp/hotarun-root
HOTARUN_DIR=/data/local/tmp/hotarun
HOTARUN_BIN=/data/local/tmp/hotarun/hotarun
HOTARUN_CONFIG_DIR=/data/local/tmp/hotarun/config
LOG=/data/local/tmp/hotarun.log
PIDFILE=/data/local/tmp/hotarun-start.pid

# --- Preflight: start only if the Hotarun setup is fully present. ---
# If anything required is missing we exit immediately WITHOUT stopping
# Android TV, so a not-yet-provisioned device is left completely untouched.
# (This runs before the singleton check / pidfile write on purpose.)
REQUIRED="
$ROOTFS/bin/sh
$HOTARUN_BIN
$HOTARUN_CONFIG_DIR/server.yml
$HOTARUN_CONFIG_DIR/tuners.yml
$HOTARUN_CONFIG_DIR/channels.yml
/data/local/tmp/tuner-stream-bs-ng
/data/local/tmp/b61dec
"
missing=""
for f in $REQUIRED; do
    { [ -e "$f" ] || [ -L "$f" ]; } || missing="$missing $f"
done
if [ -n "$missing" ]; then
    echo "[hotarun] not starting — missing file(s):$missing" >> "$LOG"
    exit 0
fi

# ACAS master key is optional for startup but required for descrambling.
if [ ! -s /data/local/tmp/.acas_key ]; then
    echo "[hotarun] warning: /data/local/tmp/.acas_key missing — streams will be scrambled." >> "$LOG"
fi

# Singleton: if another instance is already running, exit immediately.
if [ -f "$PIDFILE" ]; then
    existing=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$existing" ] && kill -0 "$existing" 2>/dev/null; then
        echo "[hotarun] already running (pid=$existing), exiting." >> "$LOG"
        exit 0
    fi
fi
echo $$ > "$PIDFILE"

# Free memory by stopping unused Android TV components (display, audio, camera,
# DRM, OEM apps, etc.).  OEM tuner services are also stopped here so b61dec can
# claim the ACAS smartcard.  See stop_android_tv.sh for the full list.
export LOG
sh /data/local/tmp/stop_android_tv.sh

# Kill stale processes from a previous session.
# NOTE: pattern "hotarun/hotarun" (not bare "hotarun") so pkill -f does not
# match this script itself (start_proxy.sh) and kill us mid-startup.
pkill -f "hotarun-proxy" 2>/dev/null || true
pkill -f "hotarun/hotarun" 2>/dev/null || true
pkill -f "tunertest_oem" 2>/dev/null || true
pkill -f "tunertest" 2>/dev/null || true
pkill -f "tuner-stream" 2>/dev/null || true
pkill -f "b61dec" 2>/dev/null || true

# --- Bind-mount host directories into the Alpine rootfs ---
mkdir -p "$ROOTFS/data/local/tmp" "$ROOTFS/system" "$ROOTFS/vendor"
mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev"

# Mount only if not already mounted (check by looking for a well-known file)
if ! test -f "$ROOTFS/data/local/tmp/hotarun/hotarun"; then
    mount --bind /data/local/tmp "$ROOTFS/data/local/tmp" 2>/dev/null || true
fi
if ! test -d "$ROOTFS/system/bin"; then
    mount --bind /system "$ROOTFS/system" 2>/dev/null || true
fi
if ! test -d "$ROOTFS/vendor/lib"; then
    mount --bind /vendor "$ROOTFS/vendor" 2>/dev/null || true
fi

# Essential kernel filesystems inside chroot
mount -t proc proc "$ROOTFS/proc" 2>/dev/null || true
mount -t sysfs sysfs "$ROOTFS/sys" 2>/dev/null || true
mount -t tmpfs tmpfs "$ROOTFS/dev" 2>/dev/null || true
# Create minimal /dev nodes inside chroot
mknod -m 666 "$ROOTFS/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/zero" c 1 5 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/urandom" c 1 9 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/random" c 1 8 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/tty" c 5 0 2>/dev/null || true

# Fix Alpine's /var/run symlink (→ /run which may not exist)
rm -f "$ROOTFS/var/run" 2>/dev/null
mkdir -p "$ROOTFS/var/run" "$ROOTFS/run"

# Create Hotarun data directories.
mkdir -p "$HOTARUN_DIR/config"

# --- Launch the brick-prevention watchdog (independent of Hotarun) ---
# crash_guard kills crash_dump32 fork-bombs and frees memory before OOM.
# Only start it if not already running.
GUARD=/data/local/tmp/crash_guard.sh
GUARD_PID=/data/local/tmp/crash_guard.pid
guard_running=0
if [ -f "$GUARD_PID" ]; then
    gp=$(cat "$GUARD_PID" 2>/dev/null)
    if [ -n "$gp" ] && kill -0 "$gp" 2>/dev/null; then
        guard_running=1
    fi
fi
if [ "$guard_running" = 0 ]; then
    setsid sh "$GUARD" >> /data/local/tmp/crash_guard.log 2>&1 &
    echo "[hotarun] crash_guard watchdog launched (pid=$!)" >> "$LOG"
else
    echo "[hotarun] crash_guard already running (pid=$gp)" >> "$LOG"
fi

echo "[hotarun] Starting Hotarun via chroot + Alpine ARM32..." >> "$LOG"

# Ensure the hotarun bind mount is present right before launch.
if ! test -f "$ROOTFS/data/local/tmp/hotarun/hotarun"; then
    mount --bind /data/local/tmp "$ROOTFS/data/local/tmp" 2>/dev/null || true
fi

# Run Hotarun ONCE — intentionally NO restart loop.
# On this device a crash-looping decoder can spawn a crash_dump32 fork-bomb
# and brick the box, so we never auto-restart.  If hotarun exits, we log and
# stop; recover with `make start` or a reboot.
# Hotarun is a glibc (Ubuntu 24.04, GLIBC_2.39) binary that Alpine's gcompat
# cannot run (segfaults in the loader stub). Use real glibc armhf libs
# deployed at /data/local/tmp/glibc-armhf (see setup_proot.sh) instead.
GLIBC_LD=/data/local/tmp/glibc-armhf/usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3
GLIBC_LIB=/data/local/tmp/glibc-armhf/usr/lib/arm-linux-gnueabihf
if [ -x "$ROOTFS$GLIBC_LD" ] || [ -x "$GLIBC_LD" ]; then
    HOTARUN_LAUNCH="$GLIBC_LD --library-path $GLIBC_LIB /data/local/tmp/hotarun/hotarun"
else
    echo "[hotarun] warning: $GLIBC_LD missing — falling back to gcompat (likely segfault)." >> "$LOG"
    HOTARUN_LAUNCH="/data/local/tmp/hotarun/hotarun"
fi
export HOTARUN_LAUNCH
chroot "$ROOTFS" /bin/sh -l -c "
    export HOTARUN_CONFIG_DIR=/data/local/tmp/hotarun/config
    cd /data/local/tmp/hotarun
    $HOTARUN_LAUNCH --config-dir /data/local/tmp/hotarun/config
" >> "$LOG" 2>&1
code=$?

echo "[hotarun] process exited (code=$code) — not restarting (safe mode)." >> "$LOG"
rm -f "$PIDFILE" 2>/dev/null || true
exit 0
