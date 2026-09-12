/*
 * acasd.c — SMB400側 ACAS daemon (SCI独占・A0/KCL epoch管理・APDU直列化).
 *
 * b61dec.c の SCI/ACAS 部分 (132-359,589-673相当) を切り出し、単一プロセスが
 * SCI を独占所有する。worker/復号は別プロセスで、UDS経由で ECM_REQ -> Ks応答
 * を受ける。master/KCLは本daemon内のみに保持し、UDS・ネットワーク・ログの
 * いずれにも出さない。UDSで返すのは Ks (odd/even 32B) のみで、0600+同一UID
 * のみ許可 (SO_PEERCRED検証)。
 *
 *  - 全APDU直列化: シングルスレッド accept->処理->応答のため直列化は自明。
 *  - ECMキャッシュ: epoch+fingerprint (len + 先頭27B) でメモリ内キャッシュ。
 *    同一ECMの連続要求はACAS呼出なし (in-flight集約相当)。
 *  - epoch: A0/KCL世代番号。起動時1、SIGHUP再認証で+1しキャッシュ破棄。
 *    reset時は全セッション世代更新として扱う (workerはepoch不一致で再取得)。
 *  - --mock / B61_MOCK=1: 実機SCIなしで決定的テスト鍵を返す (実鍵不使用)。
 *    導出: mock_kcl=SHA256("B61-MOCK-KCL-v1"), h=SHA256(mock_kcl|ecm[4..27]),
 *    odd=h[0..15], even=h[16..31]。テスト専用であり実運用では使用禁止。
 *
 * UDS protocol (short-lived, 1 conn = 1 ECM_REQ):
 *   req: [ver:1=0x01][ecm_len:2BE][ecm:ecm_len(<=148)]
 *   rep: [status:1][epoch:4BE][odd:16][even:16]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include "b61_net.h"

static volatile int g_running = 1;
static volatile int g_reauth = 0;
static uint32_t g_epoch = 1;
static int g_verbose = 0;
static int g_mock = 0;

static void on_term(int s) { (void)s; g_running = 0; }
static void on_hup(int s) { (void)s; g_reauth = 1; }

/* ---------- ECM cache (epoch + fingerprint) ---------- */
#define FP_LEN 27
struct cache_ent {
    int valid;
    int ecm_len;
    uint8_t fp[FP_LEN];
    uint8_t odd[16], even[16];
};
static struct cache_ent g_cache[B61_ACAS_CACHE_N];
static int g_cache_pos = 0;

static int cache_lookup(const uint8_t *ecm, int ecm_len,
                        uint8_t odd[16], uint8_t even[16]) {
    int k;
    for (k = 0; k < B61_ACAS_CACHE_N; k++) {
        if (!g_cache[k].valid) continue;
        if (g_cache[k].ecm_len != ecm_len) continue;
        if (memcmp(g_cache[k].fp, ecm, FP_LEN < ecm_len ? FP_LEN : ecm_len) != 0)
            continue;
        memcpy(odd, g_cache[k].odd, 16);
        memcpy(even, g_cache[k].even, 16);
        return 1;
    }
    return 0;
}

static void cache_store(const uint8_t *ecm, int ecm_len,
                        const uint8_t odd[16], const uint8_t even[16]) {
    struct cache_ent *e = &g_cache[g_cache_pos % B61_ACAS_CACHE_N];
    g_cache_pos++;
    e->valid = 1;
    e->ecm_len = ecm_len;
    memset(e->fp, 0, FP_LEN);
    memcpy(e->fp, ecm, (size_t)(ecm_len < FP_LEN ? ecm_len : FP_LEN));
    memcpy(e->odd, odd, 16);
    memcpy(e->even, even, 16);
}

static void cache_clear(void) {
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_pos = 0;
}

/* ---------- mock Ks derivation (test-only, no secrets) ---------- */
static void mock_ks(const uint8_t *ecm, int ecm_len,
                    uint8_t odd[16], uint8_t even[16]) {
    uint8_t kcl[32];
    SHA256((const unsigned char *)"B61-MOCK-KCL-v1", 15, kcl);
    uint8_t in[32 + 23];
    uint8_t ecm_part[23];
    memset(ecm_part, 0, sizeof(ecm_part));
    if (ecm_len >= 4 + 23) memcpy(ecm_part, ecm + 4, 23);
    else if (ecm_len > 4) memcpy(ecm_part, ecm + 4, (size_t)(ecm_len - 4));
    memcpy(in, kcl, 32);
    memcpy(in + 32, ecm_part, 23);
    uint8_t h[32];
    SHA256(in, sizeof(in), h);
    memcpy(odd, h, 16);
    memcpy(even, h + 16, 16);
}

/* ---------- real SCI (dlopen, same as b61dec.c) ---------- */
static void *g_lib = NULL;
typedef int (*sw_fn0)(void);
typedef int (*sw_fn3p)(uint8_t *, uint8_t *, uint8_t *);
typedef int (*sw_set_fn)(uint8_t *, int, uint8_t *, int *);
typedef int (*sw_get_fn)(uint8_t *, int *);
static sw_fn0 sw_InitAll, sw_ResetF, sw_WaitAct;
static sw_fn3p sw_GetCkc;
static sw_set_fn sw_SetData;
static sw_get_fn sw_GetData, sw_GetAtr;

static uint8_t g_kcl[32];
static int g_have_kcl = 0;

static int sci_load(void) {
    g_lib = dlopen("/vendor/lib/libstationtv_lt_px_stream.so", RTLD_NOW);
    if (!g_lib) {
        fprintf(stderr, "acasd: dlopen: %s\n", dlerror());
        return -1;
    }
#define LD(v, s) v = dlsym(g_lib, s); if (!v) { fprintf(stderr, "acasd: dlsym %s: %s\n", s, dlerror()); return -1; }
    LD(sw_InitAll, "SCI_WRAPPER_InitForAllProcess");
    LD(sw_ResetF, "SCI_WRAPPER_ResetForced");
    LD(sw_WaitAct, "SCI_WRAPPER_WaitForActivation");
    LD(sw_GetCkc, "SCI_WRAPPER_GetCkc");
    LD(sw_SetData, "SCI_WRAPPER_SetData");
    LD(sw_GetData, "SCI_WRAPPER_GetData");
    LD(sw_GetAtr, "SCI_WRAPPER_GetAtr");
#undef LD
    return 0;
}

static int acas_exchange(const uint8_t *cmd, int cmd_len,
                         uint8_t *resp, int resp_max, int *resp_len) {
    static uint8_t dummy[4];
    int dummy_len = 0;
    int r = sw_SetData((uint8_t *)cmd, cmd_len, dummy, &dummy_len);
    if (r != 0) { fprintf(stderr, "acasd: SetData err %d\n", r); return -1; }
    *resp_len = resp_max;
    r = sw_GetData(resp, resp_len);
    if (r != 0) { fprintf(stderr, "acasd: GetData err %d\n", r); return -1; }
    return 0;
}

static int acas_init_card(void) {
    static const uint8_t cmds[][5] = {
        { 0x90, 0x30, 0x00, 0x01, 0x00 },
        { 0x90, 0x32, 0x00, 0x01, 0x00 },
    };
    int i;
    for (i = 0; i < 2; i++) {
        uint8_t resp[256]; int rlen = sizeof(resp);
        if (acas_exchange(cmds[i], 5, resp, sizeof(resp), &rlen) < 0) return -1;
    }
    return 0;
}

/* A0 auth using master key file content; derives g_kcl. */
static int acas_a0_real(const uint8_t master[32]) {
    static uint8_t a0_cmd[64], a0_resp[64];
    int r = sw_GetCkc(a0_cmd, a0_resp, NULL);
    if (r != 0) { fprintf(stderr, "acasd: GetCkc failed %d\n", r); return -1; }
    const uint8_t *a0init = a0_cmd + 8;
    const uint8_t *a0resp = a0_cmd + 16;
    uint8_t in[48];
    memcpy(in, master, 32);
    memcpy(in + 32, a0init, 8);
    memcpy(in + 40, a0resp, 8);
    SHA256(in, 48, g_kcl);
    g_have_kcl = 1;
    return 0;
}

static int acas_ecm_real(const uint8_t *ecm, int ecm_len,
                         uint8_t odd[16], uint8_t even[16]) {
    if (!g_have_kcl) return -1;
    if (ecm_len < 0x1b || ecm_len > B61_ACAS_ECM_MAX) return -1;
    uint8_t cmd[5 + B61_ACAS_ECM_MAX + 1];
    cmd[0] = 0x90; cmd[1] = 0x34; cmd[2] = 0x00; cmd[3] = 0x01;
    cmd[4] = (uint8_t)ecm_len;
    memcpy(cmd + 5, ecm, (size_t)ecm_len);
    cmd[5 + ecm_len] = 0x00;
    uint8_t resp[256]; int rlen;
    if (acas_exchange(cmd, 6 + ecm_len, resp, sizeof(resp), &rlen) < 0) return -1;
    if (rlen < 2 || resp[rlen - 2] != 0x90 || resp[rlen - 1] != 0x00) return -1;
    if (rlen < 40) return -1;
    uint8_t *ecm_resp = resp + 6;
    uint8_t hd[32 + 23];
    memcpy(hd, g_kcl, 32);
    memcpy(hd + 32, ecm + 4, 23);
    uint8_t h[32];
    SHA256(hd, 55, h);
    int j;
    for (j = 0; j < 32; j++) h[j] ^= ecm_resp[j];
    memcpy(odd, h, 16);
    memcpy(even, h + 16, 16);
    return 0;
}

static int hex2byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int load_master(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "acasd: open key file failed\n"); return -1; }
    char hex[256];
    if (!fgets(hex, sizeof(hex), f)) { fclose(f); return -1; }
    fclose(f);
    /* strip ws */
    char clean[128]; int n = 0, k;
    for (k = 0; hex[k] && n < 64; k++) {
        if (hex[k] == ' ' || hex[k] == '\n' || hex[k] == '\r' || hex[k] == '\t') continue;
        clean[n++] = hex[k];
    }
    if (n != 64) { fprintf(stderr, "acasd: key must be 64 hex chars\n"); return -1; }
    int j;
    for (j = 0; j < 32; j++) {
        int hi = hex2byte(clean[j * 2]), lo = hex2byte(clean[j * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[j] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ---------- UDS helpers ---------- */
static int read_n(int fd, uint8_t *p, int n, int timeout_ms) {
    int off = 0;
    while (off < n) {
        struct pollfd pfd; pfd.fd = fd; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
        ssize_t r = read(fd, p + off, (size_t)(n - off));
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        off += (int)r;
    }
    return 0;
}

static int write_n(int fd, const uint8_t *p, int n) {
    int off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, (size_t)(n - off));
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (int)w;
    }
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [--sock <path>] [--key-file <path>] [--mock] [-v]\n"
        "\n"
        "  --sock <path>     UDS path (default " B61_ACAS_SOCK_TMP " on host,\n"
        "                    " B61_ACAS_SOCK_SMB400 " on device)\n"
        "  --key-file <path> ACAS master key file (64 hex, 0600). Not needed in --mock.\n"
        "  --mock            test mode: deterministic Ks without SCI/hardware.\n"
        "                    Also enabled by B61_MOCK=1. NEVER use with real keys.\n"
        "  -v                verbose (never logs keys)\n"
        "\n"
        "Single SCI owner. ECM_REQ->Ks over UDS (0600, same-UID only).\n"
        "SIGHUP re-authenticates (epoch+1, cache clear).\n",
        p);
}

int main(int argc, char **argv) {
    const char *sock_path = NULL;
    const char *key_file = "/data/local/tmp/.acas_key";
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) sock_path = argv[++i];
        else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) key_file = argv[++i];
        else if (strcmp(argv[i], "--mock") == 0) g_mock = 1;
        else if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "acasd: unknown arg '%s'\n", argv[i]); usage(argv[0]); return 1; }
    }
    if (getenv("B61_MOCK") && strcmp(getenv("B61_MOCK"), "1") == 0) g_mock = 1;
    if (!sock_path) {
        /* host default differs from device default */
        if (access("/vendor/lib/libstationtv_lt_px_stream.so", F_OK) == 0 && !g_mock)
            sock_path = B61_ACAS_SOCK_SMB400;
        else
            sock_path = B61_ACAS_SOCK_TMP;
    }

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGHUP, on_hup);
    signal(SIGPIPE, SIG_IGN);

    uint8_t master[32];
    memset(master, 0, sizeof(master));
    if (!g_mock) {
        if (load_master(key_file, master) < 0) {
            fprintf(stderr, "acasd: key load failed (use --mock for test)\n");
            return 1;
        }
        struct stat st;
        if (stat(key_file, &st) == 0 && (st.st_mode & 077) != 0)
            fprintf(stderr, "acasd: WARNING: key file perms %03o (should be 600)\n",
                    (unsigned)(st.st_mode & 0777));
        if (sci_load() < 0) return 1;
        if (sw_InitAll() != 0) { fprintf(stderr, "acasd: InitForAllProcess failed\n"); return 1; }
        if (sw_ResetF() != 0) { fprintf(stderr, "acasd: ResetForced failed\n"); return 1; }
        if (sw_WaitAct() != 0) { fprintf(stderr, "acasd: WaitForActivation failed\n"); return 1; }
        if (acas_a0_real(master) < 0) { fprintf(stderr, "acasd: A0 auth failed\n"); return 1; }
        memset(master, 0, sizeof(master));
        if (acas_init_card() < 0) { fprintf(stderr, "acasd: INIT failed\n"); return 1; }
        fprintf(stderr, "acasd: ACAS ready (epoch=%u)\n", g_epoch);
    } else {
        fprintf(stderr, "acasd: MOCK mode (no hardware, no real keys) epoch=%u\n", g_epoch);
    }

    unlink(sock_path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    struct sockaddr_un au;
    memset(&au, 0, sizeof(au));
    au.sun_family = AF_UNIX;
    snprintf(au.sun_path, sizeof(au.sun_path), "%s", sock_path);
    if (bind(ls, (struct sockaddr *)&au, sizeof(au)) < 0) { perror("bind"); return 1; }
    if (chmod(sock_path, 0600) < 0) { perror("chmod"); return 1; }
    if (listen(ls, 16) < 0) { perror("listen"); return 1; }
    uid_t self_uid = getuid();
    fprintf(stderr, "acasd: listen %s (uid=%d mock=%d)\n", sock_path, (int)self_uid, g_mock);

    long n_req = 0, n_hit = 0, n_err = 0;
    while (g_running) {
        if (g_reauth) {
            g_reauth = 0;
            if (!g_mock) {
                fprintf(stderr, "acasd: SIGHUP re-auth (epoch %u->%u)\n", g_epoch, g_epoch + 1);
                if (sw_ResetF() == 0 && sw_WaitAct() == 0 &&
                    load_master(key_file, master) == 0 &&
                    acas_a0_real(master) == 0 && acas_init_card() == 0) {
                    memset(master, 0, sizeof(master));
                    g_epoch++;
                    cache_clear();
                    fprintf(stderr, "acasd: re-auth OK epoch=%u\n", g_epoch);
                } else {
                    fprintf(stderr, "acasd: re-auth FAILED (keep old epoch)\n");
                    n_err++;
                }
            } else {
                g_epoch++;
                cache_clear();
                fprintf(stderr, "acasd: mock epoch=%u\n", g_epoch);
            }
        }
        struct pollfd pfd; pfd.fd = ls; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }
        if (pr == 0) continue;
        int c = accept(ls, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        /* Same-UID check */
        struct ucred cr; socklen_t crlen = sizeof(cr);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) == 0) {
            if (cr.uid != self_uid) {
                fprintf(stderr, "acasd: reject uid=%d (need %d)\n",
                        (int)cr.uid, (int)self_uid);
                uint8_t rep[1 + 4 + 32];
                rep[0] = B61_ACAS_STATUS_ERR;
                rep[1] = (g_epoch >> 24) & 0xFF; rep[2] = (g_epoch >> 16) & 0xFF;
                rep[3] = (g_epoch >> 8) & 0xFF; rep[4] = g_epoch & 0xFF;
                memset(rep + 5, 0, 32);
                (void)write_n(c, rep, sizeof(rep));
                close(c);
                n_err++;
                continue;
            }
        }

        uint8_t hdr[3];
        if (read_n(c, hdr, 3, 5000) < 0) { close(c); n_err++; continue; }
        if (hdr[0] != B61_ACAS_VERSION) { close(c); n_err++; continue; }
        int ecm_len = ((int)hdr[1] << 8) | hdr[2];
        if (ecm_len < 0x1b || ecm_len > B61_ACAS_ECM_MAX) {
            uint8_t rep[1 + 4 + 32];
            rep[0] = B61_ACAS_STATUS_ERR;
            rep[1] = (g_epoch >> 24) & 0xFF; rep[2] = (g_epoch >> 16) & 0xFF;
            rep[3] = (g_epoch >> 8) & 0xFF; rep[4] = g_epoch & 0xFF;
            memset(rep + 5, 0, 32);
            (void)write_n(c, rep, sizeof(rep));
            close(c); n_err++; continue;
        }
        uint8_t ecm[B61_ACAS_ECM_MAX];
        if (read_n(c, ecm, ecm_len, 5000) < 0) { close(c); n_err++; continue; }
        n_req++;

        uint8_t odd[16], even[16];
        int ok = 0;
        if (cache_lookup(ecm, ecm_len, odd, even)) {
            n_hit++; ok = 1;
            if (g_verbose)
                fprintf(stderr, "acasd: hit len=%d fp=%02X%02X%02X%02X epoch=%u\n",
                        ecm_len, ecm[0], ecm[1], ecm[2], ecm[3], g_epoch);
        } else if (g_mock) {
            mock_ks(ecm, ecm_len, odd, even);
            cache_store(ecm, ecm_len, odd, even);
            ok = 1;
            if (g_verbose)
                fprintf(stderr, "acasd: mock miss len=%d epoch=%u\n", ecm_len, g_epoch);
        } else {
            if (acas_ecm_real(ecm, ecm_len, odd, even) == 0) {
                cache_store(ecm, ecm_len, odd, even);
                ok = 1;
            } else {
                fprintf(stderr, "acasd: ECM APDU failed len=%d\n", ecm_len);
                n_err++;
                ok = 0;
            }
        }

        uint8_t rep[1 + 4 + 32];
        rep[0] = ok ? B61_ACAS_STATUS_OK : B61_ACAS_STATUS_ERR;
        rep[1] = (g_epoch >> 24) & 0xFF; rep[2] = (g_epoch >> 16) & 0xFF;
        rep[3] = (g_epoch >> 8) & 0xFF; rep[4] = g_epoch & 0xFF;
        if (ok) { memcpy(rep + 5, odd, 16); memcpy(rep + 5 + 16, even, 16); }
        else memset(rep + 5, 0, 32);
        /* Ks自体はログに出さない */
        if (write_n(c, rep, sizeof(rep)) < 0) n_err++;
        /* 成功Ksのメモリは即時消去 (応答送信後) */
        memset(odd, 0, sizeof(odd));
        memset(even, 0, sizeof(even));
        close(c);
    }

    close(ls);
    unlink(sock_path);
    if (!g_mock && g_lib) dlclose(g_lib);
    memset(g_kcl, 0, sizeof(g_kcl));
    memset(master, 0, sizeof(master));
    fprintf(stderr, "acasd: exit req=%ld hit=%ld err=%ld epoch=%u\n",
            n_req, n_hit, n_err, g_epoch);
    return 0;
}
