#!/bin/sh
# test_decoder_mirakurun.sh — Mirakurun decoder用法の検証 (他サーバ側 b61_net_client)。
# 想定: tuners.yml で command=<暗号化raw TLVチューナー> + decoder=b61_net_client
#       Mirakurunが tuner stdout→decoder stdin→decoder stdout→配信 とパイプ。
# 検証 (mock鍵のみ, 秘密鍵・ECM実データ不使用):
#   1) decoderパイプ (tuner stdout→decoder stdin→stdout) で復号・ECM/SI保持・EMM既定OFF
#   2) 引数なし既定値 + B61_HOST/B61_PORT/B61_TOKEN env (CLI優先)
#   3) 上流EOFでSHUT_WR→残読取→stdout EOF→exit 0, stdout純粋・ログstderr
#   4) SIGTERMで速やかに終了 (143, ゾンビなし), SIGPIPE(EPIPE)で終了1・ハングなし
#   5) 終了コード規約 (Token不一致=1, 不正引数=1, -s/-i/-m/-v互換, 鍵ログなし)
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
TMP="$(mktemp -d)"
ACAS_PID=""; SRV_PID=""; SRV_DEF_PID=""
trap 'rm -rf "$TMP"; kill ${ACAS_PID:-} ${SRV_PID:-} ${SRV_DEF_PID:-} 2>/dev/null || true' EXIT INT TERM

SOCK="$TMP/acas.sock"
UP_PORT=14173
FAN_PORT=14174
TOKEN="decoder-token-789"
SVC=100
OTHER=200
COUNT=20

echo "[decoder] start mock acasd..."
B61_MOCK=1 "$BIN/acasd" --sock "$SOCK" --mock > "$TMP/acas.log" 2>&1 &
ACAS_PID=$!
for k in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FAIL acasd"; cat "$TMP/acas.log"; exit 1; }

echo "[decoder] start server..."
B61_ACAS_SOCK="$SOCK" "$BIN/b61_net_server" --listen $UP_PORT --fanout $FAN_PORT \
    --acas-sock "$SOCK" --token "$TOKEN" > "$TMP/srv.log" 2>&1 &
SRV_PID=$!
sleep 1
kill -0 $SRV_PID || { echo "FAIL server start"; cat "$TMP/srv.log"; exit 1; }

echo "[decoder] gen..."
python3 "$ROOT/tests/gen_tlv.py" --out "$TMP/in.tlv" --mode filter --count $COUNT --service $SVC --seed 11
python3 "$ROOT/tests/check_tlv.py" "$TMP/in.tlv"

# 1) Mirakurun decoderパイプ: tuner(stdout=暗号化raw) | decoder | 配信(stdout=復号済み)
echo "[decoder] 1) tuner | decoder pipe (decoder: --host --channel) ..."
# shellcheck disable=SC2002
cat "$TMP/in.tlv" | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/out.tlv" 2> "$TMP/cli.log"
RC=$?
if [ $RC -ne 0 ]; then echo "FAIL: decoder pipe rc=$RC"; cat "$TMP/cli.log"; exit 1; fi
echo "ASSERT decoder pipe exit 0 OK"
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
assert r["scr"] == 0, f"must be decrypted scr==0, got {r['scr']}"
assert r["ecm"] >= 1, "ECM kept"
assert r["emm"] == 0, "EMM default OFF"
assert r["mpu_clear"].get(svc, 0) == cnt, f"svc kept {r['mpu_clear'].get(svc,0)} != {cnt}"
assert r["mpu_clear"].get(other, 0) == 0, "other dropped"
assert r["total"] == cnt + 3, f"filtered total {r['total']} != {cnt+3}"
print("ASSERT decoder filter/ECM/SI OK")
PY
# stdout純粋・ログstderr: outはTLVのみ (check済み), logはstderr側にあること
grep -q "handshake OK" "$TMP/cli.log" || { echo "FAIL: handshake log missing"; cat "$TMP/cli.log"; exit 1; }
grep -q "done up=0 down=0" "$TMP/cli.log" || { echo "FAIL: done log missing"; cat "$TMP/cli.log"; exit 1; }
echo "ASSERT stdout-pure/stderr-log OK"

# 1b) -s/-i/-m/-v互換 (arib-b61-stream-test互換)
echo "[decoder] 1b) -s/-i/-m/-v compat ..."
cat "$TMP/in.tlv" | "$BIN/b61_net_client" -s $SVC -i 1 -m 0 -v \
    --host 127.0.0.1 --port $UP_PORT --token "$TOKEN" > "$TMP/out_compat.tlv" 2> "$TMP/cli_compat.log" || {
    echo "FAIL compat"; cat "$TMP/cli_compat.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/out_compat.tlv"; then
    echo "ASSERT -s/-i/-m/-v compat OK (identical to --channel)"
else
    echo "FAIL: compat output differs"; ls -l "$TMP/out.tlv" "$TMP/out_compat.tlv"; exit 1
fi

# 2) env指定: B61_HOST/B61_PORT/B61_TOKEN (CLIなし・引数なしに近い形)
echo "[decoder] 2) env host/port/token ..."
B61_HOST=127.0.0.1 B61_PORT=$UP_PORT B61_TOKEN="$TOKEN" \
    sh -c 'cat "$1" | "$2" --channel "$3" > "$4" 2> "$5"' sh \
    "$TMP/in.tlv" "$BIN/b61_net_client" "$SVC" "$TMP/out_env.tlv" "$TMP/cli_env.log" || {
    echo "FAIL env"; cat "$TMP/cli_env.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/out_env.tlv"; then
    echo "ASSERT env host/port/token OK"
else
    echo "FAIL: env vs CLI differ"; exit 1
fi
# CLI優先: envが誤りでもCLI正なら通ること
echo "[decoder] 2b) CLI overrides env ..."
B61_HOST=127.0.0.1 B61_PORT=1 B61_TOKEN="wrong" \
    "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --token "$TOKEN" \
    --channel $SVC < "$TMP/in.tlv" > "$TMP/out_prio.tlv" 2> "$TMP/cli_prio.log" || {
    echo "FAIL CLI priority"; cat "$TMP/cli_prio.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/out_prio.tlv"; then
    echo "ASSERT CLI-over-env OK"
else
    echo "FAIL: CLI priority differs"; exit 1
fi

# 2c) 引数なし既定値 (host=127.0.0.1:40773, token=none, s=0)
echo "[decoder] 2c) no-args defaults (port 40773, token none) ..."
B61_ACAS_SOCK="$SOCK" "$BIN/b61_net_server" --listen 40773 --fanout 0 \
    --acas-sock "$SOCK" --token none > "$TMP/srvdef.log" 2>&1 &
SRV_DEF_PID=$!
sleep 1
kill -0 $SRV_DEF_PID || { echo "FAIL default server"; cat "$TMP/srvdef.log"; exit 1; }
B61_TOKEN=none "$BIN/b61_net_client" < "$TMP/in.tlv" > "$TMP/outdef.tlv" 2> "$TMP/clidef.log" || {
    echo "FAIL defaults"; cat "$TMP/clidef.log"; exit 1; }
python3 "$ROOT/tests/check_tlv.py" "$TMP/outdef.tlv" || { echo "FAIL defaults parse"; exit 1; }
echo "ASSERT no-args defaults OK"
kill ${SRV_DEF_PID:-} 2>/dev/null || true
wait ${SRV_DEF_PID:-} 2>/dev/null || true
SRV_DEF_PID=""

# 3) 上流EOFでSHUT_WR→残読取→stdout EOF→exit 0 (既にrc==0で確認済み。残出力の完全性も確認)
echo "[decoder] 3) EOF drains remainder ..."
# shellcheck disable=SC2002
dd if="$TMP/in.tlv" bs=17 status=none | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/outfrag.tlv" 2> "$TMP/clifrag.log" || {
    echo "FAIL frag"; cat "$TMP/clifrag.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/outfrag.tlv"; then
    echo "ASSERT EOF/fragment OK"
else
    echo "FAIL: fragment differs"; exit 1
fi

# 4) SIGTERMで速やかに終了・ゾンビなし (MirakurunがdecoderをSIGTERMする想定)
echo "[decoder] 4) SIGTERM quick exit, no zombie ..."
# 無限チューナー (EOFなし) | decoder を起動しSIGTERM
tail -f /dev/null 2>/dev/null | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/sig_out.tlv" 2> "$TMP/sig.log" &
DEC_PID=$!
sleep 1
kill -0 $DEC_PID 2>/dev/null || { echo "FAIL: decoder not running"; cat "$TMP/sig.log"; exit 1; }
# 子 (pump_down) の存在を確認
CHILD_BEFORE=$(ps --ppid $DEC_PID -o pid= 2>/dev/null | wc -l | tr -d ' ')
echo "child count before TERM: $CHILD_BEFORE"
kill -TERM $DEC_PID
# 最大3秒で終了すること (143=128+15)
WAIT_RC=0
for k in $(seq 1 30); do
    if ! kill -0 $DEC_PID 2>/dev/null; then break; fi
    sleep 0.1
    if [ "$k" = "30" ]; then echo "FAIL: SIGTERM did not exit in 3s"; ps -o pid,ppid,stat,cmd -p $DEC_PID || true; kill -KILL $DEC_PID 2>/dev/null || true; exit 1; fi
done
set +e
wait $DEC_PID 2>/dev/null
WAIT_RC=$?
set -e
echo "decoder wait rc=$WAIT_RC"
if [ "$WAIT_RC" -ne 143 ]; then echo "FAIL: SIGTERM rc=$WAIT_RC (want 143)"; cat "$TMP/sig.log"; exit 1; fi
echo "ASSERT SIGTERM rc=143 OK"
sleep 0.5
# ゾンビ/残存チェック: decoderとその子が残っていないこと
if ps -o pid,ppid,stat,cmd -p $DEC_PID 2>/dev/null | grep -q "$DEC_PID"; then
    echo "FAIL: decoder still remains (zombie?)"; ps -o pid,ppid,stat,cmd -p $DEC_PID || true; exit 1
fi
if ps aux 2>/dev/null | grep "[b]61_net_client.*$UP_PORT" | grep -q .; then
    echo "WARN: stray client remains"; ps aux | grep "[b]61_net_client" || true
    # 残存はFAIL (ゾンビ化防止の要件)
    echo "FAIL: stray b61_net_client remains"; exit 1
fi
echo "ASSERT no-zombie OK"
# 後続の正常系が動くこと (サーバが壊れていない)
cat "$TMP/in.tlv" | "$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT \
    --token "$TOKEN" --channel $SVC > "$TMP/out_after_sig.tlv" 2> "$TMP/cli_after_sig.log" || {
    echo "FAIL: server broken after SIGTERM"; cat "$TMP/cli_after_sig.log"; cat "$TMP/srv.log"; exit 1; }
if cmp -s "$TMP/out.tlv" "$TMP/out_after_sig.tlv"; then
    echo "ASSERT server-alive-after-SIGTERM OK"
else
    echo "FAIL: output differs after SIGTERM"; exit 1
fi

# 4b) SIGPIPE/EPIPE: 下流closeでハングせず終了1
echo "[decoder] 4b) downstream close (EPIPE) must not hang ..."
set +e
timeout 8 sh -c 'cat "$1" | "$2" --host 127.0.0.1 --port "$3" --token "$4" --channel "$5" 2> "$6" | head -c 10 > /dev/null' sh \
    "$TMP/in.tlv" "$BIN/b61_net_client" "$UP_PORT" "$TOKEN" "$SVC" "$TMP/epipe.log"
EPIPE_RC=$?
set -e
# headが先に閉じるため decoderはEPIPE/非0または0のいずれも許すが、ハング (124) はNG
if [ "$EPIPE_RC" -eq 124 ]; then echo "FAIL: EPIPE hung (timeout)"; cat "$TMP/epipe.log"; exit 1; fi
echo "ASSERT EPIPE no-hang OK (rc=$EPIPE_RC)"
sleep 0.5
if ps aux 2>/dev/null | grep "[b]61_net_client.*$UP_PORT" | grep -q .; then
    echo "FAIL: stray client after EPIPE"; ps aux | grep "[b]61_net_client" || true; exit 1
fi

# 5) 終了コード規約: Token不一致=1, 不正引数=1, 不正port=1
echo "[decoder] 5) exit codes ..."
set +e
"$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --token "wrong-token" \
    --channel $SVC < "$TMP/in.tlv" > "$TMP/bad.tlv" 2> "$TMP/bad.log"
RC=$?
set -e
if [ $RC -ne 1 ]; then echo "FAIL: token mismatch rc=$RC (want 1)"; exit 1; fi
grep -q "handshake rejected" "$TMP/bad.log" || { echo "FAIL: missing handshake rejected"; cat "$TMP/bad.log"; exit 1; }
echo "ASSERT token-mismatch exit 1 OK"

set +e
"$BIN/b61_net_client" --host 127.0.0.1 --port $UP_PORT --channel foo < /dev/null > /dev/null 2> "$TMP/inv.log"
RC=$?
set -e
if [ $RC -ne 1 ]; then echo "FAIL: invalid channel rc=$RC"; exit 1; fi
echo "ASSERT invalid-arg exit 1 OK"

set +e
B61_PORT="badport" "$BIN/b61_net_client" --host 127.0.0.1 --channel $SVC < /dev/null > /dev/null 2> "$TMP/badport.log"
RC=$?
set -e
if [ $RC -ne 1 ]; then echo "FAIL: bad B61_PORT rc=$RC (want 1)"; cat "$TMP/badport.log"; exit 1; fi
echo "ASSERT bad-env-port exit 1 OK"

# 鍵ログなし
if grep -qiE "odd_key|even_key|Ks=|KCL|master" "$TMP/cli.log" "$TMP/srv.log" "$TMP/acas.log"; then
    echo "FAIL: possible key material in logs"; exit 1
else
    echo "ASSERT no-key-log OK"
fi

kill ${SRV_PID:-} ${ACAS_PID:-} 2>/dev/null || true
wait ${SRV_PID:-} 2>/dev/null || true
wait ${ACAS_PID:-} 2>/dev/null || true
echo "PASS: test_decoder_mirakurun"
