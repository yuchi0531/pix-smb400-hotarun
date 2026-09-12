#!/bin/sh
# test_tlv_boundary.sh — P0相当: TLV境界・順序維持。
# gen(boundary) -> dd(bs=17で断片化) -> b61_select_filter -s 0 -> out が入力と同一。
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "[boundary] gen..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode boundary --count 120 --seed 7
echo "[boundary] filter with fragmentation..."
# shellcheck disable=SC2002
dd if="$TMP/in.tlv" bs=17 status=none | "$BIN/b61_select_filter" -s 0 -i 1 -m 0 > "$TMP/out.tlv" 2> "$TMP/stderr.log"
RC=$?
if [ $RC -ne 0 ]; then echo "FAIL: filter exit=$RC"; cat "$TMP/stderr.log" >&2; exit 1; fi
if cmp -s "$TMP/in.tlv" "$TMP/out.tlv"; then
    echo "PASS: boundary/order preserved (cmp identical)"
else
    echo "FAIL: output differs from input"
    ls -l "$TMP/in.tlv" "$TMP/out.tlv"
    python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv" || true
    python3 "$ROOT/tests/check_tlv.py" "$TMP/out.tlv" || true
    exit 1
fi
# stdout純粋: stderrに統計はあるが、stdoutはTLVのみ (cmpで保証済み)。
# 先頭バイトが7Fであることも確認
python3 "$ROOT/tests/check_tlv.py" "$TMP/out.tlv"
echo "PASS: test_tlv_boundary"
