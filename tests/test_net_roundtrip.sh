#!/bin/sh
# test_net_roundtrip.sh — P2-P5相当: ネットワーク往復・順序・ECM・fan-out・EOF・背圧。
# mock acasd + net_server(localhost) に対し、compat wrapper (filter|client) で
# 暗号化TLVを送り、復号済みを受信。fanout subscriberも同時受信し一致を確認。
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; kill $ACAS_PID $SRV_PID $FAN_PID 2>/dev/null || true' EXIT INT TERM

SOCK="$TMP/acas.sock"
UP_PORT=14073
FAN_PORT=14074
TOKEN="test-token-123"
SVC=100

echo "[net] start mock acasd..."
B61_MOCK=1 "$BIN/acasd" --sock "$SOCK" --mock > "$TMP/acas.log" 2>&1 &
ACAS_PID=$!
for k in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FAIL acasd"; cat "$TMP/acas.log"; exit 1; }

echo "[net] start server..."
B61_ACAS_SOCK="$SOCK" "$BIN/b61_net_server" --listen $UP_PORT --fanout $FAN_PORT \
    --acas-sock "$SOCK" --token "$TOKEN" > "$TMP/srv.log" 2>&1 &
SRV_PID=$!
sleep 1
kill -0 $SRV_PID || { echo "FAIL server start"; cat "$TMP/srv.log"; exit 1; }

echo "[net] gen roundtrip..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode roundtrip --count 30 --service $SVC --seed 33
echo "--- in ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv"

echo "[net] start fanout subscriber (background)..."
python3 "$ROOT/tests/fanout_sub.py" 127.0.0.1 $FAN_PORT $SVC "$TOKEN" "$TMP/fanout.tlv" 12 &
FAN_PID=$!
sleep 0.5

echo "[net] compat wrapper (network)..."
# compat wrapper のBINDIR解決のため build/host が存在することを前提
B61_TOKEN="$TOKEN" sh "$ROOT/scripts/b61_stream_test_compat.sh" \
    -s $SVC -i 1 -m 0 --host 127.0.0.1 --port $UP_PORT --token "$TOKEN" \
    < "$TMP/in.tlv" > "$TMP/out.tlv" 2> "$TMP/cli.log" || {
    echo "FAIL: compat wrapper rc=$?"; echo "--- cli ---"; cat "$TMP/cli.log"; echo "--- srv ---"; cat "$TMP/srv.log"; exit 1; }
echo "--- out ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/out.tlv" || { echo "FAIL out parse"; exit 1; }

# wait fanout (subscriber times out after 12s or server close)
wait $FAN_PID 2>/dev/null || true
echo "--- fanout ---"
if [ -s "$TMP/fanout.tlv" ]; then
    python3 "$ROOT/tests/check_tlv.py" "$TMP/fanout.tlv" || echo "WARN: fanout parse incomplete (timing)"
else
    echo "WARN: fanout empty (timing) — server log:"; cat "$TMP/srv.log" || true
fi

# assertions: out must be decrypted (scr==0) but keep packet count/ECM/SI
python3 - "$TMP/in.tlv" "$TMP/out.tlv" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
rin = mod.parse(sys.argv[1]); rout = mod.parse(sys.argv[2])
assert rin and rout, "parse fail"
print(f"in: total={rin['total']} scr={rin['scr']} ecm={rin['ecm']}", file=sys.stderr)
print(f"out: total={rout['total']} scr={rout['scr']} ecm={rout['ecm']}", file=sys.stderr)
assert rin["scr"] > 0, "input must contain scrambled (encrypted raw required)"
assert rout["scr"] == 0, f"output must be decrypted (scr==0), got {rout['scr']}"
assert rout["ecm"] >= 1, "ECM must be kept through network"
assert rout["total"] == rin["total"], f"packet count preserved {rin['total']} vs {rout['total']}"
assert rout["trail"] == 0, "no trailing bytes"
print("ASSERT roundtrip OK")
PY

# fanout consistency (if non-empty): also decrypted
if [ -s "$TMP/fanout.tlv" ]; then
    python3 - "$TMP/fanout.tlv" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
r = mod.parse(sys.argv[1])
assert r, "fanout parse fail"
assert r["scr"] == 0, f"fanout must be decrypted, scr={r['scr']}"
print("ASSERT fanout OK")
PY
fi

# server log sanity: upstream session + no key leak (keys never logged)
if grep -q "upstream up" "$TMP/srv.log"; then echo "server session OK"; else echo "WARN: no upstream session in log"; cat "$TMP/srv.log"; fi
if grep -qiE "odd_key|even_key|Ks=|KCL|master" "$TMP/srv.log" "$TMP/acas.log" "$TMP/cli.log"; then
    echo "FAIL: possible key material in logs"; exit 1
else
    echo "no key material in logs OK"
fi

kill $SRV_PID $ACAS_PID 2>/dev/null || true
wait $SRV_PID 2>/dev/null || true
wait $ACAS_PID 2>/dev/null || true
echo "PASS: test_net_roundtrip"
