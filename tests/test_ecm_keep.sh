#!/bin/sh
# test_ecm_keep.sh — P1相当: ECM保持・service選択・EMM既定OFF。
# gen(filter, service=100) には svc=100 MPU + other=200 MPU + ECM + SI + EMM + Null。
# -s 100 -m 0 で: 100保持、200除去、ECM/SI/Null保持、EMM除去。
# -s 100 -m 1 で: EMM保持。
# -s 0 で: 全保持 (互換)。
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

SVC=100
OTHER=200
COUNT=20

echo "[ecm] gen..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode filter --count $COUNT --service $SVC --seed 11
echo "--- input ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv"

echo "[ecm] filter -s $SVC -m 0..."
"$BIN/b61_select_filter" -s $SVC -i 1 -m 0 < "$TMP/in.tlv" > "$TMP/out0.tlv" 2> "$TMP/f0.log" || { echo "FAIL filter m0"; cat "$TMP/f0.log"; exit 1; }
echo "--- out m0 ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/out0.tlv"

# assertions via python
python3 - "$TMP/out0.tlv" $SVC $OTHER $COUNT <<'PY'
import sys
sys.path.insert(0, sys.argv[0] and "tests" or "tests")
# avoid path issues: import via file
import importlib.util
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out, svc, other, cnt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
r = mod.parse(out)
assert r is not None, "parse fail"
assert r["trail"] == 0, f"trailing {r['trail']}"
assert r["ecm"] >= 1, f"ECM must be kept, got {r['ecm']}"
assert r["emm"] == 0, f"EMM must be dropped with -m 0, got {r['emm']}"
assert r["mpu"].get(svc, 0) == cnt, f"svc {svc} kept {r['mpu'].get(svc,0)} != {cnt}"
assert r["mpu"].get(other, 0) == 0, f"other {other} must be dropped, got {r['mpu'].get(other,0)}"
assert r["sig"] >= 1, "SI must be kept"
print("ASSERT m0 OK")
PY

echo "[ecm] filter -s $SVC -m 1 (EMM keep)..."
"$BIN/b61_select_filter" -s $SVC -i 1 -m 1 < "$TMP/in.tlv" > "$TMP/out1.tlv" 2> "$TMP/f1.log" || { echo "FAIL filter m1"; cat "$TMP/f1.log"; exit 1; }
python3 "$ROOT/tests/check_tlv.py" "$TMP/out1.tlv"
python3 - "$TMP/out1.tlv" <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
import sys
r = mod.parse(sys.argv[1])
assert r["emm"] >= 1, f"EMM must be kept with -m 1, got {r['emm']}"
print("ASSERT m1 OK")
PY

echo "[ecm] filter -s 0 (all pass)..."
"$BIN/b61_select_filter" -s 0 < "$TMP/in.tlv" > "$TMP/outA.tlv" 2> "$TMP/fA.log" || exit 1
if cmp -s "$TMP/in.tlv" "$TMP/outA.tlv"; then
    echo "ASSERT all-pass OK (identical)"
else
    # -m 0 drops EMM, so not identical when EMM present; check MPU both kept
    python3 - "$TMP/outA.tlv" $SVC $OTHER $COUNT <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out, svc, other, cnt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
r = mod.parse(out)
assert r["mpu"].get(svc,0)==cnt and r["mpu"].get(other,0)==cnt, f"both services kept: {r['mpu']}"
print("ASSERT all-pass MPU OK (EMM dropped by -m 0 as designed)")
PY
fi

echo "PASS: test_ecm_keep"
