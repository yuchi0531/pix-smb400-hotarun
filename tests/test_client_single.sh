#!/bin/sh
# test_client_single.sh — b61_net_client単体完結の検証 (他サーバ使い方2つ)。
# 要件:
#   recpt1 | b61_net_client --host SMB400 --channel XXX | 出力
#   b61_net_client < encrypted.tlv > decrypted.tlv
# + Token不一致はERRで終了1、遅延・切断・再接続の振る舞い明確化。
# mock acasd + net_server (localhost) に対し、filter無しでclient単体を検証。
# 合成パターン+mockのみ (秘密鍵・ECM実データ不使用)。
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
ACAS_PID=""; SRV_PID=""; SRV_DEF_PID=""
trap 'rm -rf "$TMP"; kill ${ACAS_PID:-} ${SRV_PID:-} ${SRV_DEF_PID:-} 2>/dev/null || true' EXIT INT TERM

SOCK="$TMP/acas.sock"
UP_PORT=14075
FAN_PORT=14076
TOKEN="single-token-456"
SVC=100
OTHER=200
COUNT=20

echo "[single] start mock acasd..."
B61_MOCK=1 "$BIN/acasd" --sock "$SOCK" --mock > "$TMP/acas.log" 2>&1 &
ACAS_PID=$!
for k in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FAIL acasd"; cat "$TMP/acas.log"; exit 1; }

echo "[single] start server..."
B61_ACAS_SOCK="$SOCK" "$BIN/b61_net_server" --listen $UP_PORT --fanout $FAN_PORT \
    --acas-sock "$SOCK" --token "$TOKEN" > "$TMP/srv.log" 2>&1 &
SRV_PID=$!
sleep 1
kill -0 $SRV_PID || { echo "FAIL server start"; cat "$TMP/srv.log"; exit 1; }

echo "[single] gen..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode filter --count $COUNT --service $SVC --seed 11
python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv"

echo "[single] 1) recpt1-style pipe: cat | b61_net_client --host ... --channel SVC ..."
# shellcheck disable=SC2002
cat "$TMP/in.tlv" | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/out.tlv" 2> "$TMP/cli.log" || {
    echo "FAIL: single client rc=$?"; cat "$TMP/cli.log"; cat "$TMP/srv.log"; exit 1; }
echo "--- out (single) ---"
python3 "$ROOT/tests/check_tlv.py" "$TMP/out.tlv" || { echo "FAIL out parse"; exit 1; }

python3 - "$TMP/out.tlv" $SVC $OTHER $COUNT <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out, svc, other, cnt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
r = mod.parse(out)
assert r is not None, "parse fail"
assert r["trail"] == 0, f"trailing {r['trail']}"
assert r["scr"] == 0, f"output must be decrypted scr==0, got {r['scr']}"
assert r["ecm"] >= 1, "ECM must be kept"
# decrypted MPU are counted in mpu_clear (scr==0 after decrypt)
assert r["mpu_clear"].get(svc, 0) == cnt, f"svc {svc} kept {r['mpu_clear'].get(svc,0)} != {cnt}"
assert r["mpu_clear"].get(other, 0) == 0, f"other {other} must be dropped by --channel, got {r['mpu_clear'].get(other,0)}"
assert r["emm"] == 0, "EMM default OFF must be dropped"
# filtered total: SI+ECM+20*MPU100+Null = 23 (unfiltered would be 43)
assert r["total"] == cnt + 3, f"filtered total {r['total']} != {cnt+3}"
print("ASSERT single-channel OK")
PY

# 2) file redirect form with explicit host (same binary, stdin file):
echo "[single] 2) file redirect: b61_net_client < encrypted.tlv > decrypted.tlv ..."
"$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --token "$TOKEN" \
    --channel $SVC < "$TMP/in.tlv" > "$TMP/out2.tlv" 2> "$TMP/cli2.log" || {
    echo "FAIL: file redirect rc=$?"; cat "$TMP/cli2.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/out2.tlv"; then
    echo "ASSERT file-redirect OK (identical to pipe)"
else
    echo "FAIL: pipe vs redirect differ"
    ls -l "$TMP/out.tlv" "$TMP/out2.tlv"; exit 1
fi

# 2b) defaults form: b61_net_client < in > out (host=127.0.0.1:40773, token=none)
echo "[single] 2b) defaults: b61_net_client < in > out (port 40773, token none) ..."
B61_ACAS_SOCK="$SOCK" "$BIN/b61_net_server" --listen 40773 --fanout 0 \
    --acas-sock "$SOCK" --token none > "$TMP/srvdef.log" 2>&1 &
SRV_DEF_PID=$!
sleep 1
kill -0 $SRV_DEF_PID || { echo "FAIL default server start"; cat "$TMP/srvdef.log"; exit 1; }
# use -s 0 default? input has 2 services; default s=0 keeps both (except EMM drop).
# For determinism use channel via -s? No — bare defaults must also work (all-pass).
B61_TOKEN=none "$BIN/b61_net_client" < "$TMP/in.tlv" > "$TMP/outdef.tlv" 2> "$TMP/clidef.log" || {
    echo "FAIL: defaults rc=$?"; cat "$TMP/clidef.log"; cat "$TMP/srvdef.log"; exit 1; }
python3 "$ROOT/tests/check_tlv.py" "$TMP/outdef.tlv" || { echo "FAIL defaults parse"; exit 1; }
python3 - "$TMP/outdef.tlv" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check", "tests/check_tlv.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
r = mod.parse(sys.argv[1])
assert r is not None and r["scr"] == 0, f"defaults must decrypt scr==0, got {r}"
assert r["ecm"] >= 1, "ECM kept"
print("ASSERT defaults OK")
PY
kill ${SRV_DEF_PID:-} 2>/dev/null || true
wait ${SRV_DEF_PID:-} 2>/dev/null || true
SRV_DEF_PID=""

# 3) Token mismatch -> ERR exit 1 (no auto-retry, caller must reconnect)
echo "[single] 3) token mismatch must fail with exit 1 ..."
set +e
"$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --token "wrong-token" \
    --channel $SVC < "$TMP/in.tlv" > "$TMP/bad.tlv" 2> "$TMP/bad.log"
RC=$?
set -e
if [ $RC -ne 1 ]; then echo "FAIL: token mismatch rc=$RC (want 1)"; cat "$TMP/bad.log"; exit 1; fi
if grep -q "handshake rejected" "$TMP/bad.log"; then
    echo "ASSERT token-mismatch OK (ERR, exit 1, no retry)"
else
    echo "FAIL: missing handshake rejected in log"; cat "$TMP/bad.log"; exit 1
fi
if grep -q "upstream up" "$TMP/srv.log"; then echo "server session exists OK"; fi
if grep -q "token mismatch" "$TMP/srv.log"; then echo "server reject logged OK"; else echo "WARN: server log missing token mismatch"; fi

# 4) invalid --channel -> exit 1 (usage error, no network)
echo "[single] 4) invalid --channel ..."
set +e
"$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --channel foo < /dev/null > /dev/null 2> "$TMP/inv.log"
RC=$?
set -e
if [ $RC -ne 1 ]; then echo "FAIL: invalid channel rc=$RC"; cat "$TMP/inv.log"; exit 1; fi
echo "ASSERT invalid-channel OK"

# 5) fragmentation: dd bs=17 through single client keeps order/boundary
echo "[single] 5) fragmentation via client ..."
# shellcheck disable=SC2002
dd if="$TMP/in.tlv" bs=17 status=none | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/outfrag.tlv" 2> "$TMP/clifrag.log" || {
    echo "FAIL: frag rc=$?"; cat "$TMP/clifrag.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/outfrag.tlv"; then
    echo "ASSERT fragmentation OK (identical)"
else
    echo "FAIL: fragmentation output differs"; ls -l "$TMP/out.tlv" "$TMP/outfrag.tlv"; exit 1
fi

# stdout pure + no key material + EOF exit 0 already asserted by rc==0 above
if grep -qiE "odd_key|even_key|Ks=|KCL|master" "$TMP/cli.log" "$TMP/srv.log" "$TMP/acas.log"; then
    echo "FAIL: possible key material in logs"; exit 1
else
    echo "no key material in logs OK"
fi
grep -q "upstream done" "$TMP/cli.log" || { echo "FAIL: client filter stats missing"; cat "$TMP/cli.log"; exit 1; }

kill ${SRV_PID:-} ${ACAS_PID:-} 2>/dev/null || true
wait ${SRV_PID:-} 2>/dev/null || true
wait ${ACAS_PID:-} 2>/dev/null || true
echo "PASS: test_client_single"
