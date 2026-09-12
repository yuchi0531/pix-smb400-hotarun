/*
 * b61_net.h — network protocol constants (host + SMB400 shared).
 *
 * 方式D: 復号はSMB400内で完結。ネットワーク上を流れるのは TLV バイト列のみで、
 * master/KCL/Ks をネットワーク・IPC(UDS外)・ログに出さない。
 * TLS 自体は stunnel/WireGuard 等の外側で終端する想定で、本プロトコルは平文TCP
 * 上で短命Tokenによるハンドシェイクを行う。
 *
 * Upstream (selector -> server, full-duplex echo):
 *   C: "B61/1 TOKEN <tok> SERVICE <s> SID <i>\n"   (tok最大128文字, 空なら"none")
 *   S: "B61/1 OK\n"  または "B61/1 ERR <reason>\n"
 *   以降 C->S: 選択済み暗号化TLVバイト列 (TLV境界・順序はTCPに委譲、受信側で再組立)
 *   以降 S->C: 復号済みTLVバイト列 (同一TCP full-duplex echo)
 *   Cは stdin EOFで SHUT_WR (FIN) し、Sの復号残を読み切って close まで待つ。
 *
 * Fanout (server -> viewers, one-way):
 *   C: "B61/1 SUBSCRIBE SERVICE <s> TOKEN <tok>\n"
 *   S: "B61/1 OK\n"  または ERR
 *   以降 S->C: 復号済みTLVバイト列のみ。遅いclientは個別切断。
 */
#ifndef B61_NET_H
#define B61_NET_H

#define B61_NET_VERSION            "B61/1"
#define B61_NET_DEFAULT_PORT       40773
#define B61_NET_DEFAULT_FANOUT     40774
#define B61_NET_TOKEN_MAX          128
#define B61_NET_LINE_MAX           512
#define B61_NET_MAX_TLV            (4 + 65535)

/* 有界キュー (背圧用). これを超えたら upstream は読取を止める (block)、
 * fanout 遅延clientは個別切断する。 */
#define B61_NET_UP_BUF_BYTES       (4 * 1024 * 1024)
#define B61_NET_DOWN_BUF_BYTES     (4 * 1024 * 1024)
#define B61_NET_FANOUT_PER_CLIENT  (8 * 1024 * 1024)
#define B61_NET_ECHO_PENDING_MAX   (8 * 1024 * 1024)

#define B61_NET_HANDSHAKE_TIMEOUT_MS 5000
#define B61_NET_SEND_TIMEOUT_MS      5000

/* UDS (acasd <-> worker, 同一ホスト・同一UID限定) */
#define B61_ACAS_SOCK_SMB400 "/data/local/tmp/.acas.sock"
#define B61_ACAS_SOCK_TMP    "/tmp/b61_acas.sock"
#define B61_ACAS_VERSION     0x01U
#define B61_ACAS_ECM_MAX     148
#define B61_ACAS_CACHE_N     16

/* UDS request:  [ver:1][ecm_len:2BE][ecm:ecm_len]
 * UDS reply:    [status:1][epoch:4BE][odd:16][even:16]
 *   status 0=OK, 1=ERR (odd/evenは無効), epochはdaemonの世代番号。
 */
#define B61_ACAS_STATUS_OK  0
#define B61_ACAS_STATUS_ERR 1

#endif /* B61_NET_H */
