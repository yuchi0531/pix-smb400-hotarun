/*
 * b61_select_filter.c — 他サーバ側 select-filter.
 *
 * stdin=暗号化raw TLV -> stdout=選択済みTLV (順序・TLV境界維持、stdout純粋)。
 * ログは全てstderr。stdin EOFで残りの完成パケットを出し切って exit 0。
 *
 * 選択規則 (方式D・NG回避):
 *  - 暗号化raw TLVを入力とすること (復号済み再入力は警告のみで素通ししない)。
 *    判定は enc_flag ではなく「ECMが来ているか・scrambled MPUがあるか」で行い、
 *    全パケット平文なら stderr に警告を出す (復号済み再復号NGの検出用)。
 *  - NTP/TLV-SI/CAT/PLT/MPT/ECM は常に保持 (非HC TLV + 非scrambled-MPU HCは保持)。
 *  - scrambled MPU のみ service フィルタ対象:
 *      -s 0 (既定): 全通し (互換・全TLV転送NGは -s指定時のみ回避される)。
 *      -s <id>: pkt_id == (id & 0xFFFF) のMPUのみ保持、他は落とす。
 *      MPT学習前の簡易規則として文書化 (MPT自体は保持されるので下流で再選択可)。
 *  - EMMは既定OFF (-m 0): EMMヒューリスティックに一致したら落とす。
 *    -m 1 で保持。
 *  - -i <n> (既定1): 互換のため受け付けるセッション表示用ID。フィルタ動作に
 *    影響しない (ハンドシェイクのSIDとしてそのまま運ばれる)。
 *  - -v: 1パケット毎の判定をstderrに出す。
 *
 * 終了コード: 0=正常(EOF含む)、1=引数・I/Oエラー。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "b61_tlv.h"

#define SEL_BUFSZ (4 * 1024 * 1024)

static int g_verbose = 0;

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [-s <service_id>] [-i <session_id>] [-m <0|1>] [-v]\n"
        "\n"
        "  -s <id>  service id (default 0 = all services, no filtering)\n"
        "  -i <id>  session id for logging/handshake (default 1, no filter effect)\n"
        "  -m <0|1> EMM handling: 0=drop (default), 1=keep\n"
        "  -v       verbose per-packet log to stderr\n"
        "\n"
        "Reads encrypted raw TLV from stdin, writes selected TLV to stdout.\n"
        "Order and TLV boundaries are preserved. Logs go to stderr only.\n"
        "NTP/TLV-SI/CAT/PLT/MPT/ECM are always kept. Only scrambled MPU is\n"
        "filtered by -s. EMM is dropped by default (-m 0).\n",
        p);
}

int main(int argc, char **argv) {
    long service = 0;
    long sess = 1;
    int emm_keep = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            service = strtol(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            sess = strtol(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            emm_keep = atoi(argv[++i]) ? 1 : 0;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "b61_select_filter: unknown arg '%s'\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    fprintf(stderr,
        "b61_select_filter: start (service=%ld session=%ld emm=%s)\n",
        service, sess, emm_keep ? "keep" : "drop");

    uint8_t *buf = (uint8_t *)malloc(SEL_BUFSZ);
    if (!buf) { perror("malloc"); return 1; }
    int len = 0;        /* valid bytes */
    int base = 0;       /* processed offset */

    long n_in = 0, n_out = 0, n_drop_mpu = 0, n_drop_emm = 0;
    long n_scrambled = 0, n_ecm = 0;
    int eof = 0;

    while (!eof || base < len) {
        /* Fill */
        if (!eof && len < SEL_BUFSZ) {
            ssize_t n = read(STDIN_FILENO, buf + len, (size_t)(SEL_BUFSZ - len));
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("b61_select_filter: read");
                free(buf);
                return 1;
            }
            if (n == 0) eof = 1;
            else len += (int)n;
        }
        /* Process complete packets */
        int pos = base;
        int progressed = 0;
        while (pos + 4 <= len) {
            if (buf[pos] != B61_TLV_HEADER_BYTE) {
                int j = pos + 1;
                while (j < len && buf[j] != B61_TLV_HEADER_BYTE) j++;
                if (j >= len) break; /* need more data (or EOF drop) */
                if (g_verbose)
                    fprintf(stderr, "b61_select_filter: resync %d->%d\n", pos, j);
                pos = j;
                continue;
            }
            int dl = (int)b61_u16be(buf + pos + 2);
            if (dl > B61_TLV_MAX_DATA) { pos++; continue; }
            int pl = 4 + dl;
            if (pos + pl > len) break; /* incomplete */
            /* One complete TLV packet at buf+pos, length pl */
            const uint8_t *pkt = buf + pos;
            uint8_t tlv_type = pkt[1];
            n_in++;

            int keep = 1;
            const char *reason = "pass";

            /* EMM heuristic (applies to any TLV carrying CA EMM) */
            if (!emm_keep && b61_contains_emm(pkt, pl)) {
                keep = 0; reason = "drop-emm";
                n_drop_emm++;
            } else if (tlv_type == B61_TLV_TYPE_NULL) {
                keep = 1; reason = "keep-null";
            } else if (tlv_type != B61_TLV_TYPE_HC) {
                keep = 1; reason = "keep-signal";
                const uint8_t *ep = NULL; int el = 0;
                b61_find_ecm(pkt, pl, &ep, &el);
                if (ep) { n_ecm++; reason = "keep-ecm"; }
            } else {
                /* HC packet */
                const uint8_t *ep = NULL; int el = 0;
                b61_find_ecm(pkt, pl, &ep, &el);
                if (ep) {
                    n_ecm++;
                    keep = 1; reason = "keep-ecm";
                } else {
                    uint16_t pid = 0;
                    int scr = b61_is_scrambled_mpu(pkt, pl, &pid);
                    if (!scr) {
                        keep = 1; reason = "keep-hc-signal";
                    } else {
                        n_scrambled++;
                        if (service == 0) {
                            keep = 1; reason = "keep-mpu-all";
                        } else if (pid == (uint16_t)(service & 0xFFFF)) {
                            keep = 1; reason = "keep-mpu-hit";
                        } else {
                            keep = 0; reason = "drop-mpu";
                            n_drop_mpu++;
                        }
                    }
                }
            }

            if (g_verbose) {
                uint16_t pid = 0;
                (void)b61_is_scrambled_mpu(pkt, pl, &pid);
                fprintf(stderr,
                    "b61_select_filter: tlv=0x%02X len=%d %s%s\n",
                    tlv_type, pl, reason,
                    (tlv_type == B61_TLV_TYPE_HC) ? "" : "");
            }

            if (keep) {
                if (b61_write_all(STDOUT_FILENO, pkt, pl) < 0) {
                    perror("b61_select_filter: write");
                    free(buf);
                    return 1;
                }
                n_out++;
            }
            pos += pl;
            progressed = 1;
        }
        base = pos;
        /* Compact */
        if (base > 0) {
            if (base < len) memmove(buf, buf + base, (size_t)(len - base));
            len -= base;
            base = 0;
        }
        /* Buffer full with no progress: drop one byte (resync) */
        if (!eof && len == SEL_BUFSZ && !progressed) {
            memmove(buf, buf + 1, (size_t)(len - 1));
            len--;
            if (g_verbose) fprintf(stderr, "b61_select_filter: buf full, drop 1B\n");
        }
        /* EOF with trailing incomplete bytes: drop + log */
        if (eof && base == len) break;
        if (eof && len - base < 4 && len - base > 0) {
            fprintf(stderr,
                "b61_select_filter: drop %d trailing incomplete byte(s) at EOF\n",
                len - base);
            break;
        }
        if (eof && len - base >= 4) {
            /* Check if remaining can form a packet; if not enough data, drop */
            int pl = b61_tlv_pkt_len(buf + base, len - base);
            if (pl < 0 || base + pl > len) {
                fprintf(stderr,
                    "b61_select_filter: drop %d trailing byte(s) at EOF\n",
                    len - base);
                break;
            }
            /* else loop continues (progress possible) */
            if (!progressed) {
                fprintf(stderr,
                    "b61_select_filter: drop %d trailing byte(s) at EOF\n",
                    len - base);
                break;
            }
        }
        if (eof && !progressed && base == 0 && len == 0) break;
        if (eof && len == 0) break;
    }

    free(buf);
    fprintf(stderr,
        "b61_select_filter: done in=%ld out=%ld ecm=%ld scrambled=%ld "
        "drop_mpu=%ld drop_emm=%ld\n",
        n_in, n_out, n_ecm, n_scrambled, n_drop_mpu, n_drop_emm);
    if (n_scrambled == 0 && n_ecm == 0 && n_in > 0)
        fprintf(stderr,
            "b61_select_filter: WARNING: no scrambled MPU/ECM seen "
            "(input may already be decrypted; re-decrypt is NG)\n");
    if (service != 0 && n_scrambled > 0 && n_ecm == 0)
        fprintf(stderr,
            "b61_select_filter: WARNING: scrambled MPU without ECM "
            "(service-filtered input must keep ECM; decrypt would fail)\n");
    return 0;
}
