#!/bin/sh
# run_all.sh — local tests runner (no device, no secrets).
set -eu
ROOT="$(dirname "$0")/.."
BIN="$ROOT/build/host"
for b in b61_select_filter b61_net_client acasd b61dec_worker b61_net_server; do
    if [ ! -x "$BIN/$b" ]; then echo "missing $BIN/$b (run: make build-host)"; exit 1; fi
done
chmod +x "$ROOT/tests/"*.sh "$ROOT/tests/"*.py "$ROOT/scripts/b61_stream_test_compat.sh"
sh "$ROOT/tests/test_tlv_boundary.sh"
sh "$ROOT/tests/test_ecm_keep.sh"
sh "$ROOT/tests/test_eof.sh"
sh "$ROOT/tests/test_net_roundtrip.sh"
sh "$ROOT/tests/test_client_single.sh"
sh "$ROOT/tests/test_decoder_mirakurun.sh"
echo "ALL PASS"
