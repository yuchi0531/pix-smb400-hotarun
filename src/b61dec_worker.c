/*
 * b61dec_worker.c — SMB400側 復号worker (b61dec.cからSCI分離).
 *
 * b61dec.c の TLV/ECM/復号コア (362-502,679-877相当) を切り出し、SCI/APDUは
 * 一切持たず、ECM解決のみ acasd (UDS) に委譲する。master/KCLは扱わない。
 * Ksはメモリのみに保持し、IPC外・ログに出さない。
 *
 * stdin=暗号化raw TLV -> stdout=復号済みTLV (順序・TLV境界維持、stdout純粋)。
 * NTP/TLV-SI/CAT/PLT/MPT/ECM保持、複数ECM・鍵更新追従、先頭バッファリング、
 * stdin EOFで残出力して exit 0。EMMはここでは落とさない (filter側で制御)。
 *
 * 終了コード: 0=正常、1=引数・acasd接続・I/Oエラー。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "b61_tlv.h"
#include "b61_net.h"
#include "b61_acas_client.h"

static long g_tlv_total, g_hc, g_ext, g_scr, g_dec, g_ecm;
static int g_verbose = 0;
static const char *g_acas_sock = NULL;
static uint32_t g_epoch_seen = 0;

/* ---------- AES-128-CTR (b61dec.cと同一: bulk EVP) ---------- */
static EVP_CIPHER_CTX *g_ctx_odd, *g_ctx_even;
static uint8_t g_key_odd[16], g_key_even[16];
static int g_key_odd_set, g_key_even_set;

static int aes_ctr_init(void) {
    g_ctx_odd = EVP_CIPHER_CTX_new();
    g_ctx_even = EVP_CIPHER_CTX_new();
    return (g_ctx_odd && g_ctx_even) ? 0 : -1;
}

static void aes_ctr_decrypt(int is_odd, const uint8_t key[16],
                            const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, int len) {
    EVP_CIPHER_CTX *ctx = is_odd ? g_ctx_odd : g_ctx_even;
    uint8_t *curkey = is_odd ? g_key_odd : g_key_even;
    int *kset = is_odd ? &g_key_odd_set : &g_key_even_set;
    if (!*kset || memcmp(curkey, key, 16) != 0) {
        memcpy(curkey, key, 16);
        *kset = 1;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    } else {
        EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
    }
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, len);
}

/* In-place decrypt (b61dec.c decrypt_tlv_inplace と同一判定) */
static int decrypt_tlv_inplace(uint8_t *tlv, int len,
                               const uint8_t *odd_key,
                               const uint8_t *even_key) {
    if (len < 4) return 0;
    uint8_t tlv_type = tlv[1];
    int data_len = (int)b61_u16be(tlv + 2);
    if (4 + data_len != len) return 0;
    if (tlv_type != B61_TLV_TYPE_HC) return 0;
    g_hc++;
    if (data_len < 3) return 0;
    uint8_t hc_type = tlv[6];
    int mmtp_off;
    if (hc_type == B61_HC_NO_COMP) mmtp_off = 7;
    else if (hc_type == B61_HC_PART_V6) mmtp_off = 4 + 0x2D;
    else return 0;
    const uint8_t *mmtp = tlv + mmtp_off;
    int mmtp_len = len - mmtp_off;
    if (mmtp_len < B61_MMTP_OFF_ENC + 1) return 0;
    uint8_t flags = mmtp[B61_MMTP_OFF_FLAGS];
    int has_ext = (flags & 0x02) != 0;
    int has_pcnt = (flags & 0x20) != 0;
    if (!has_ext || has_pcnt) return 0;
    g_ext++;
    uint16_t mext = b61_u16be(mmtp + B61_MMTP_OFF_MEXT_T);
    uint8_t enc_byte = mmtp[B61_MMTP_OFF_ENC];
    int enc_flag = (enc_byte & 0x18) >> 3;
    if ((mext & 0x7FFF) != 0x0001) return 0;
    if (enc_flag == B61_ENC_NONE) return 0;
    g_scr++;
    if (!odd_key || !even_key) return 0;
    if ((mmtp[B61_MMTP_OFF_TYPE] & 0x3F) != 0x00) return 0;
    uint8_t iv[16];
    memset(iv, 0, 16);
    iv[0] = mmtp[B61_MMTP_OFF_PKT_ID];     iv[1] = mmtp[B61_MMTP_OFF_PKT_ID + 1];
    iv[2] = mmtp[B61_MMTP_OFF_SEQ];        iv[3] = mmtp[B61_MMTP_OFF_SEQ + 1];
    iv[4] = mmtp[B61_MMTP_OFF_SEQ + 2];    iv[5] = mmtp[B61_MMTP_OFF_SEQ + 3];
    int is_odd = (enc_flag == B61_ENC_ODD);
    const uint8_t *key = is_odd ? odd_key : even_key;
    uint16_t ext_len = b61_u16be(mmtp + B61_MMTP_OFF_EXT_L);
    int payload_off = 0x0C + (int)ext_len + 4;
    int enc_start = payload_off + 8;
    int enc_len = mmtp_len - enc_start;
    if (enc_start > mmtp_len || enc_len <= 0) return 0;
    tlv[mmtp_off + B61_MMTP_OFF_ENC] = enc_byte & 0xE3;
    aes_ctr_decrypt(is_odd, key, iv,
                    tlv + mmtp_off + enc_start,
                    tlv + mmtp_off + enc_start,
                    enc_len);
    g_dec++;
    return 1;
}

/* ---------- Ks cache (epoch + fingerprint, 複数ECM対応) ---------- */
#define WK_CACHE_N 16
#define WK_FP_LEN 27
struct wk_ent {
    int valid;
    uint32_t epoch;
    int ecm_len;
    uint8_t fp[WK_FP_LEN];
    uint8_t odd[16], even[16];
};
static struct wk_ent g_wcache[WK_CACHE_N];
static int g_wpos = 0;

static int wk_lookup(const uint8_t *ecm, int ecm_len, uint32_t epoch,
                     uint8_t odd[16], uint8_t even[16]) {
    int k;
    for (k = 0; k < WK_CACHE_N; k++) {
        if (!g_wcache[k].valid) continue;
        if (g_wcache[k].epoch != epoch && epoch != 0) continue;
        if (g_wcache[k].ecm_len != ecm_len) continue;
        int cmp = ecm_len < WK_FP_LEN ? ecm_len : WK_FP_LEN;
        if (memcmp(g_wcache[k].fp, ecm, (size_t)cmp) != 0) continue;
        memcpy(odd, g_wcache[k].odd, 16);
        memcpy(even, g_wcache[k].even, 16);
        return 1;
    }
    return 0;
}

static void wk_store(const uint8_t *ecm, int ecm_len, uint32_t epoch,
                     const uint8_t odd[16], const uint8_t even[16]) {
    struct wk_ent *e = &g_wcache[g_wpos % WK_CACHE_N];
    g_wpos++;
    e->valid = 1;
    e->epoch = epoch;
    e->ecm_len = ecm_len;
    memset(e->fp, 0, WK_FP_LEN);
    memcpy(e->fp, ecm, (size_t)(ecm_len < WK_FP_LEN ? ecm_len : WK_FP_LEN));
    memcpy(e->odd, odd, 16);
    memcpy(e->even, even, 16);
}

static void wk_clear(void) {
    memset(g_wcache, 0, sizeof(g_wcache));
    g_wpos = 0;
}

/* ECM解決: ローカルcache -> acasd。成功で odd/even を返す。Ksはログ禁止。 */
static int resolve_ecm(const uint8_t *ecm, int ecm_len,
                       uint8_t odd[16], uint8_t even[16]) {
    if (wk_lookup(ecm, ecm_len, g_epoch_seen, odd, even)) return 0;
    uint8_t n_odd[16], n_even[16];
    uint32_t epoch = 0;
    if (b61_acas_request(g_acas_sock, ecm, ecm_len, n_odd, n_even, &epoch) < 0)
        return -1;
    if (g_epoch_seen != 0 && epoch != g_epoch_seen) {
        fprintf(stderr, "b61dec_worker: epoch %u->%u, clear local cache\n",
                g_epoch_seen, epoch);
        wk_clear();
    }
    g_epoch_seen = epoch;
    /* epoch不一致でlookupし直し (clear後の再登録前) */
    wk_store(ecm, ecm_len, epoch, n_odd, n_even);
    memcpy(odd, n_odd, 16);
    memcpy(even, n_even, 16);
    memset(n_odd, 0, sizeof(n_odd));
    memset(n_even, 0, sizeof(n_even));
    return 0;
}

static void print_stats(void) {
    fprintf(stderr, "\nb61dec_worker stats:\n");
    fprintf(stderr, "  TLV packets total    : %ld\n", g_tlv_total);
    fprintf(stderr, "  HeaderCompressed     : %ld\n", g_hc);
    fprintf(stderr, "  With extension hdr   : %ld\n", g_ext);
    fprintf(stderr, "  Scrambled (enc!=0)   : %ld\n", g_scr);
    fprintf(stderr, "  Decrypted            : %ld\n", g_dec);
    fprintf(stderr, "  ECM packets found    : %ld\n", g_ecm);
    if (g_scr > 0 && g_dec == 0)
        fprintf(stderr, "  WARNING: scrambled but NONE decrypted!\n");
    if (g_scr > 0 && g_dec < g_scr)
        fprintf(stderr, "  NOTE: %ld scrambled NOT decrypted (no keys yet)\n",
                g_scr - g_dec);
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [--acas-sock <path>] [-v] [-s <id>] [-i <id>] [-m <0|1>]\n"
        "\n"
        "  --acas-sock <path>  acasd UDS path (default auto)\n"
        "  -v                  verbose\n"
        "  -s/-i/-m            accepted for compat (no filter effect here)\n"
        "\n"
        "Reads encrypted raw TLV from stdin, writes decrypted TLV to stdout.\n"
        "ECM resolution via acasd only. No master keys here.\n",
        p);
}

int main(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--acas-sock") == 0 && i + 1 < argc) g_acas_sock = argv[++i];
        else if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-i") == 0 ||
                  strcmp(argv[i], "-m") == 0) && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "b61dec_worker: unknown arg '%s'\n", argv[i]); usage(argv[0]); return 1; }
    }
    if (!g_acas_sock) {
        const char *e = getenv("B61_ACAS_SOCK");
        if (e && *e) g_acas_sock = e;
        else if (access("/vendor/lib/libstationtv_lt_px_stream.so", F_OK) == 0)
            g_acas_sock = B61_ACAS_SOCK_SMB400;
        else
            g_acas_sock = B61_ACAS_SOCK_TMP;
    }

    if (aes_ctr_init() < 0) { fprintf(stderr, "b61dec_worker: EVP init failed\n"); return 1; }

    /* acasd到達確認 (ECMが来る前の早期失敗用に軽くPOLL: 実ECMなしでは未接続でも進む) */
    fprintf(stderr, "b61dec_worker: acas sock %s\n", g_acas_sock);

    uint8_t odd_key[16], even_key[16];
    int have_keys = 0;

#define IOBUF_SIZE   (16 * 1024 * 1024)
#define PRESCAN_SIZE (8 * 1024 * 1024)
#define PRESCAN_TIMEOUT_MS 10000
    uint8_t *buf = (uint8_t *)malloc(IOBUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }
    int buf_len = 0, write_base = 0;

    /* Prescan: 先頭バッファリングで最初のECMを待つ (b61dec.cと同一) */
    fprintf(stderr, "b61dec_worker: pre-scanning for first ECM...\n");
    while (!have_keys && buf_len < PRESCAN_SIZE) {
        struct pollfd pfd; pfd.fd = STDIN_FILENO; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, PRESCAN_TIMEOUT_MS);
        if (pr < 0) { perror("prescan poll"); break; }
        if (pr == 0) {
            fprintf(stderr, "b61dec_worker: prescan timeout, proceed without ECM\n");
            break;
        }
        ssize_t n = read(STDIN_FILENO, buf + buf_len, (size_t)(PRESCAN_SIZE - buf_len));
        if (n < 0) { perror("prescan read"); break; }
        if (n == 0) break;
        buf_len += (int)n;
        int scan_pos = 0;
        while (scan_pos + 4 <= buf_len) {
            if (buf[scan_pos] != B61_TLV_HEADER_BYTE) { scan_pos++; continue; }
            int dl = (int)b61_u16be(buf + scan_pos + 2);
            int pl = 4 + dl;
            if (dl > B61_TLV_MAX_DATA) { scan_pos++; continue; }
            if (scan_pos + pl > buf_len) break;
            const uint8_t *ep = NULL; int el = 0;
            b61_find_ecm(buf + scan_pos, pl, &ep, &el);
            if (ep && el >= 0x1b) {
                uint8_t n_odd[16], n_even[16];
                g_ecm++;
                if (resolve_ecm(ep, el, n_odd, n_even) == 0) {
                    memcpy(odd_key, n_odd, 16);
                    memcpy(even_key, n_even, 16);
                    memset(n_odd, 0, sizeof(n_odd));
                    memset(n_even, 0, sizeof(n_even));
                    have_keys = 1;
                    fprintf(stderr,
                        "b61dec_worker: prescan ECM at offset %d, decrypt from start\n",
                        scan_pos);
                } else {
                    fprintf(stderr, "b61dec_worker: prescan ECM resolve failed (acasd?)\n");
                }
            }
            scan_pos += pl;
            if (have_keys) break;
        }
    }
    if (!have_keys)
        fprintf(stderr,
            "b61dec_worker: WARNING: ECM not in prescan (%d bytes). "
            "Initial packets may remain encrypted.\n", buf_len);

    /* stdin EOFでも残バッファを出し切って exit 0 (互換IF) */
    int eof = 0;
    while (!eof || write_base < buf_len) {
        if (!eof && buf_len < IOBUF_SIZE) {
            ssize_t n = read(STDIN_FILENO, buf + buf_len, (size_t)(IOBUF_SIZE - buf_len));
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("read");
                break;
            }
            if (n == 0) eof = 1;
            else buf_len += (int)n;
        }
        int pos = write_base;
        while (pos + 4 <= buf_len) {
            if (buf[pos] != B61_TLV_HEADER_BYTE) {
                int j;
                for (j = pos + 1; j < buf_len - 1; j++)
                    if (buf[j] == B61_TLV_HEADER_BYTE) { pos = j; break; }
                if (buf[pos] != B61_TLV_HEADER_BYTE) break;
            }
            if (pos + 4 > buf_len) break;
            int data_len = (int)b61_u16be(buf + pos + 2);
            int pkt_len = 4 + data_len;
            if (data_len > B61_TLV_MAX_DATA) { pos++; continue; }
            if (pos + pkt_len > buf_len) break;
            g_tlv_total++;
            int decrypted = 0;
            if (pkt_len > 4) {
                decrypted = decrypt_tlv_inplace(buf + pos, pkt_len,
                                                have_keys ? odd_key : NULL,
                                                have_keys ? even_key : NULL);
            }
            if (!decrypted) {
                const uint8_t *ecm_ptr = NULL; int ecm_len_v = 0;
                b61_find_ecm(buf + pos, pkt_len, &ecm_ptr, &ecm_len_v);
                if (ecm_ptr && ecm_len_v > 0 && ecm_len_v >= 0x1b) {
                    uint8_t cur_odd[16], cur_even[16];
                    /* ローカルcacheで新規性判定 (acasd側でもcache) */
                    if (!wk_lookup(ecm_ptr, ecm_len_v, g_epoch_seen, cur_odd, cur_even)) {
                        g_ecm++;
                        uint8_t n_odd[16], n_even[16];
                        if (resolve_ecm(ecm_ptr, ecm_len_v, n_odd, n_even) == 0) {
                            memcpy(odd_key, n_odd, 16);
                            memcpy(even_key, n_even, 16);
                            memset(n_odd, 0, sizeof(n_odd));
                            memset(n_even, 0, sizeof(n_even));
                            if (!have_keys)
                                fprintf(stderr, "b61dec_worker: keys obtained\n");
                            have_keys = 1;
                        }
                    } else {
                        memcpy(odd_key, cur_odd, 16);
                        memcpy(even_key, cur_even, 16);
                        have_keys = 1;
                    }
                }
            }
            pos += pkt_len;
        }
        if (pos > write_base) {
            int out_len = pos - write_base;
            if (b61_write_all(STDOUT_FILENO, buf + write_base, out_len) < 0) {
                free(buf);
                goto done;
            }
            write_base = pos;
        }
        if (write_base > 0) {
            memmove(buf, buf + write_base, (size_t)(buf_len - write_base));
            buf_len -= write_base;
            write_base = 0;
        }
        if (!eof && buf_len == IOBUF_SIZE && pos == write_base) {
            memmove(buf, buf + 1, (size_t)(buf_len - 1));
            buf_len--;
        }
        if (eof && pos == write_base) {
            if (buf_len - write_base > 0)
                fprintf(stderr, "b61dec_worker: drop %d trailing byte(s) at EOF\n",
                        buf_len - write_base);
            break;
        }
    }

done:
    /* stdin EOF: 残出力は上ループで書き切り済み。Ks消去して exit 0 */
    memset(odd_key, 0, sizeof(odd_key));
    memset(even_key, 0, sizeof(even_key));
    memset(g_wcache, 0, sizeof(g_wcache));
    free(buf);
    print_stats();
    if (g_ctx_odd) EVP_CIPHER_CTX_free(g_ctx_odd);
    if (g_ctx_even) EVP_CIPHER_CTX_free(g_ctx_even);
    return 0;
}
