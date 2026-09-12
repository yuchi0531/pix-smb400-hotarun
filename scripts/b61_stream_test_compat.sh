#!/bin/sh
# b61_stream_test_compat.sh — arib-b61-stream-test代替 互換CLIラッパー。
#
# stdin=暗号化raw TLV -> stdout=復号済みTLV (順序・TLV境界維持、stdout純粋)。
# ログは全てstderr。-s/-i/-m/-v互換 (既定 s=0,i=1,m=0)。NTP/TLV-SI/CAT/PLT/
# MPT/ECM保持、複数ECM・鍵更新追従、先頭バッファリング、stdin EOFで残出力
# して exit 0、EMM既定OFF。
#
# 方式D: 復号はSMB400内で完結。master/KCL/Ksを外部・IPC(UDS外)・ログに出さない。
# 本ラッパーは他サーバ側で select-filter -> net_client を組み立て、SMB400側の
# b61_net_server (+acasd/worker) へ1TCPで送り、復号済みをstdoutへ返す。
# TLSは stunnel/WireGuard 等の外側で終端する想定。短命Tokenは --token/$B61_TOKEN。
#
# NG (文書化):
#  - serviceフィルタ入力の復号: filterはECMを必ず保持する。ECM欠き警告が出たらNG。
#  - 復号済み再復号: 平文入力は警告を出し、そのまま素通ししない (server側で検出)。
#  - 全TLV転送: -s指定時はMPUを絞る (既定s=0は全通し互換のため例外)。
#  - ECM-only鍵返却: KsはUDS同一UID内のみ。ネットワークに鍵は流さない。
#
# Usage:
#   b61_stream_test_compat.sh [-s <service>] [-i <sid>] [-m <0|1>] [-v]
#       [--host <h>] [--port <n>] [--token <t>] [--channel <id>] [--local] [--mock-sock <path>]
#   例:
#     cat enc.tlv | b61_stream_test_compat.sh -s 0 --host smb400 --port 40773 > dec.tlv
#     cat enc.tlv | b61_stream_test_compat.sh --channel 100 --host smb400 > dec100.tlv
#     cat enc.tlv | b61_stream_test_compat.sh --local --mock-sock /tmp/b61_acas.sock > dec.tlv
#
# --channel は -s の別名 (例: --channel 100)。単体 b61_net_client も同一。
# --local: ネットワークを使わず select-filter | b61dec_worker (要acasd起動済み)。
#
# 単体完結の使い方 (ラッパー不要。client内蔵filterで必要分のみ送信):
#   recpt1 --channel 100 | b61_net_client --host SMB400 --channel 100 | 出力
#   b61_net_client --host SMB400 --channel 100 < encrypted.tlv > decrypted.tlv

set -eu

S=0
I=1
M=0
VERBOSE=0
HOST="127.0.0.1"
PORT="40773"
TOKEN="${B61_TOKEN:-none}"
LOCAL=0
MOCK_SOCK="${B61_ACAS_SOCK:-/tmp/b61_acas.sock}"
BINDIR="$(dirname "$0")/../build/host"
# 実機配置では /data/local/tmp を見る (hostビルド物と同名)。存在すれば優先。
if [ ! -x "$BINDIR/b61_select_filter" ] && [ -x "/data/local/tmp/b61_select_filter" ]; then
    BINDIR="/data/local/tmp"
fi
# リポジトリ直下build/hostが無ければ、スクリプトと同階層のbuild/hostも探す
if [ ! -x "$BINDIR/b61_select_filter" ]; then
    for cand in "$(dirname "$0")/build/host" "./build/host" "/tmp/b61_build"; do
        if [ -x "$cand/b61_select_filter" ]; then BINDIR="$cand"; break; fi
    done
fi

usage() {
    echo "Usage: $0 [-s <service>] [-i <sid>] [-m <0|1>] [-v] [--host <h>] [--port <n>] [--token <t>] [--channel <id>] [--local] [--mock-sock <p>]" >&2
    echo "  defaults: -s 0 -i 1 -m 0 (EMM drop), --host 127.0.0.1 --port 40773" >&2
    echo "  --channel <id> is an alias of -s" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s) S="$2"; shift 2 ;;
        --channel) S="$2"; shift 2 ;;
        --channel=*) S="${1#--channel=}"; shift ;;
        --service) S="$2"; shift 2 ;;
        --service=*) S="${1#--service=}"; shift ;;
        -i) I="$2"; shift 2 ;;
        -m) M="$2"; shift 2 ;;
        -v) VERBOSE=1; shift ;;
        --host) HOST="$2"; shift 2 ;;
        --host=*) HOST="${1#--host=}"; shift ;;
        --port) PORT="$2"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        --token) TOKEN="$2"; shift 2 ;;
        --token=*) TOKEN="${1#--token=}"; shift ;;
        --local) LOCAL=1; shift ;;
        --mock-sock) MOCK_SOCK="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "$0: unknown arg '$1'" >&2; usage; exit 1 ;;
    esac
done

VFLAG=""
if [ "$VERBOSE" = "1" ]; then VFLAG="-v"; fi

FILTER="$BINDIR/b61_select_filter"
CLIENT="$BINDIR/b61_net_client"
WORKER="$BINDIR/b61dec_worker"

if [ "$LOCAL" = "1" ]; then
    if [ ! -x "$FILTER" ] || [ ! -x "$WORKER" ]; then
        echo "$0: local binaries not found under $BINDIR (run: make build-host)" >&2
        exit 1
    fi
    # shellcheck disable=SC2086
    exec "$FILTER" -s "$S" -i "$I" -m "$M" $VFLAG | \
         "$WORKER" --acas-sock "$MOCK_SOCK" $VFLAG
else
    if [ ! -x "$FILTER" ] || [ ! -x "$CLIENT" ]; then
        echo "$0: binaries not found under $BINDIR (run: make build-host)" >&2
        exit 1
    fi
    export B61_TOKEN="$TOKEN"
    # shellcheck disable=SC2086
    exec "$FILTER" -s "$S" -i "$I" -m "$M" $VFLAG | \
         "$CLIENT" -s "$S" -i "$I" -m "$M" $VFLAG --host "$HOST" --port "$PORT" --token "$TOKEN"
fi
