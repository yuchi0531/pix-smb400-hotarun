#!/bin/sh
# test_eof.sh — P相当: stdin EOFで残出力して exit 0、stdout純粋・ログstderr。
# gen(eof) -> filter -> worker(mock acasd) -> out。EOF後の残パケット・終了コードを確認。
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; kill $ACAS_PID 2>/dev/null || true' EXIT INT TERM

SOCK="$TMP/acas.sock"
echo "[eof] start mock acasd..."
B61_MOCK=1 "$BIN/acasd" --sock "$SOCK" --mock > "$TMP/acas.log" 2>&1 &
ACAS_PID=$!
for k in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FAIL: acasd sock missing"; cat "$TMP/acas.log"; exit 1; }

echo "[eof] gen..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode eof --service 100 --seed 21
python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv"

echo "[eof] filter | worker..."
B61_ACAS_SOCK="$SOCK" sh -c '"$1" -s 100 -m 0 < "$2" 2> "$3" | "$4" --acas-sock "$5" > "$6" 2> "$7"' sh \
    "$BIN/b61_select_filter" "$TMP/in.tlv" "$TMP/f.log" "$BIN/b61dec_worker" "$SOCK" "$TMP/out.tlv" "$TMP/w.log"
RC=$?
echo "pipeline exit=$RC"
if [ $RC -ne 0 ]; then echo "FAIL: pipeline rc=$RC"; echo "--- filter ---"; cat "$TMP/f.log"; echo "--- worker ---"; cat "$TMP/w.log"; exit 1; fi

echo "--- out ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/out.tlv" || { echo "FAIL: out not TLV"; exit 1; }

# stdout純粋: outは全て7F始まりTLV (checkで保証)。stderrに統計があること
grep -q "b61_select_filter: done" "$TMP/f.log" || { echo "FAIL: filter stats missing"; cat "$TMP/f.log"; exit 1; }
grep -q "b61dec_worker stats" "$TMP/w.log" || { echo "FAIL: worker stats missing"; cat "$TMP/w.log"; exit 1; }
# 復号確認: worker stats Decrypted > 0
if grep -q "Decrypted            : 0" "$TMP/w.log"; then echo "FAIL: nothing decrypted"; cat "$TMP/w.log"; exit 1; fi

kill $ACAS_PID 2>/dev/null || true
wait $ACAS_PID 2>/dev/null || true
echo "PASS: test_eof"
