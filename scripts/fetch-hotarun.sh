#!/bin/bash
# fetch-hotarun.sh — download the latest Hotarun ARM32 binary from GitHub Releases.
#
# Hotarun publishes fixed-name assets on every `v*` tag release
# (.github/workflows/release.yml). This script always resolves the
# `latest` release, so no version is pinned here:
#   https://github.com/yuchi0531/Hotarun/releases/latest/download/hotarun-linux-arm32
#   https://github.com/yuchi0531/Hotarun/releases/latest/download/hotarun-linux-arm32.sha256
#
# Usage (from the repository root):
#   bash scripts/fetch-hotarun.sh [output-dir]
#
# Output: <output-dir>/hotarun-linux-arm32 (+ .sha256), verified and chmod +x.
# Used by `make fetch-hotarun` / `make deploy-hotarun`.

set -euo pipefail

HOTARUN_REPO="yuchi0531/Hotarun"
HOTARUN_BIN="hotarun-linux-arm32"
BASE_URL="https://github.com/${HOTARUN_REPO}/releases/latest/download"

OUT_DIR="${1:-tmp}"
mkdir -p "$OUT_DIR"

echo "[*] Fetching latest Hotarun release (${HOTARUN_BIN})..."
curl -fL -o "${OUT_DIR}/${HOTARUN_BIN}" "${BASE_URL}/${HOTARUN_BIN}"
curl -fL -o "${OUT_DIR}/${HOTARUN_BIN}.sha256" "${BASE_URL}/${HOTARUN_BIN}.sha256"

echo "[*] Verifying SHA-256..."
(cd "$OUT_DIR" && sha256sum -c "${HOTARUN_BIN}.sha256")

chmod +x "${OUT_DIR}/${HOTARUN_BIN}"
echo "[+] Done: ${OUT_DIR}/${HOTARUN_BIN}"
ls -lh "${OUT_DIR}/${HOTARUN_BIN}"
